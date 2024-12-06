import time
import threading
from scapy.all import sniff, IP, TCP
from collections import defaultdict, Counter
import math
import os
import json
from colorama import Fore, Style
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from queue import Queue

# Constants
MIN_ACTIVE_IPS = 3
MONITOR_INTERVAL = 2
TIME_WINDOW = 5
THRESHOLD_SYN_COUNT = 100
BLOCKED_IPS = set()
ENTROPY = 0
CHI_SQUARE = 1

global threshold
threshold = None

# Set the base threshold based on the type of method used
if ENTROPY == 1:
    threshold = 0.5
elif CHI_SQUARE == 1:
    threshold = 100

# Dictionary to store timestamps of SYN packets from each IP
ip_syn_tracker = defaultdict(list)
lock = threading.Lock()

# Queue for entropy plotting
entropy_queue = Queue()

class DynamicThreshold:
    # init of the class
    def __init__(self, window_size=10, base_threshold=0.5):
        self.window_size = window_size
        self.entropy_history = []
        self.base_threshold = base_threshold

    # update the threshold
    # method for updating the threshold: calculate the average entropy of the last window_size i.e 10 entropies
    # and then calculate the dynamic threshold by taking 20% of the difference between the base threshold and the average entropy
    def update(self, entropy):
        self.entropy_history.append(entropy)
        if len(self.entropy_history) < self.window_size:
            return self.base_threshold
        if len(self.entropy_history) > self.window_size:
            self.entropy_history.pop(0)
        if self.base_threshold < 1e-20:
            return self.base_threshold
        avg_entropy = sum(self.entropy_history) / len(self.entropy_history)
        dynamic_threshold = avg_entropy + (self.base_threshold - avg_entropy) * 0.2
        self.base_threshold = dynamic_threshold
        return dynamic_threshold

# Create an instance of the DynamicThreshold class
dynamic_threshold = DynamicThreshold(window_size=10, base_threshold=threshold)

# func to calculate entropy
def calculate_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0
    entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
    print(counter.values())
    return entropy

# func to monitor entropy and detect DDoS
def monitor_entropy():
    while True:
        time.sleep(MONITOR_INTERVAL)
        current_time = time.time()
        
        with lock:
            # remove old entries outside the time window
            simplified_ip_syn_tracker = {ip: len(timestamps) for ip, timestamps in ip_syn_tracker.items()}
            with open("log.txt", "a") as log_file:
                log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {json.dumps(simplified_ip_syn_tracker)}\n")

            for ip in list(ip_syn_tracker.keys()):
                ip_syn_tracker[ip] = [t for t in ip_syn_tracker[ip] if current_time - t <= TIME_WINDOW]
                if not ip_syn_tracker[ip]:
                    del ip_syn_tracker[ip]

            
            # entropy calculation
            counter = Counter({ip: len(timestamps) for ip, timestamps in ip_syn_tracker.items()})
            entropy = calculate_entropy(counter)
            
            # use entropy data to the plot thread
            current_time_str = time.strftime("%H:%M:%S")
            entropy_queue.put((current_time_str, entropy))
            
            # check the number of active IPs and entropy
            print(f"[INFO] Entropy: {entropy}, Active IPs: {len(counter)}, IPs: {list(counter.keys())}")    

            # update the threshold as per the update method of the DynamicThreshold class
            global threshold
            threshold = dynamic_threshold.update(entropy)
            print(f"[INFO] Threshold: {threshold}")
            
            # check if the entropy is below the threshold and the number of active IPs is greater than the minimum active IPs
            if entropy < threshold and len(counter) > 0 and entropy > 0:
                print("[ALERT] Possible DDoS attack detected!")
                for ip, count in counter.items():
                    if count > THRESHOLD_SYN_COUNT and ip not in BLOCKED_IPS:
                        block_ip(ip)
                        BLOCKED_IPS.add(ip)

# func to monitor chi-square and detect DDoS
def monitor_chi_square():
    while True:
        time.sleep(MONITOR_INTERVAL)
        current_time = time.time()
        with lock:
            # remove the old entries outside the time window
            simplified_ip_syn_tracker = {ip: len(timestamps) for ip, timestamps in ip_syn_tracker.items()}
            with open("log.txt", "a") as log_file:
                log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {json.dumps(simplified_ip_syn_tracker)}\n")
            
            for ip in list(ip_syn_tracker.keys()):
                ip_syn_tracker[ip] = [t for t in ip_syn_tracker[ip] if current_time - t <= TIME_WINDOW]
                if not ip_syn_tracker[ip]:
                    del ip_syn_tracker[ip]
            
            # calculate the chi-square
            counter = Counter({ip: len(timestamps) for ip, timestamps in ip_syn_tracker.items()})
            print(f"[INFO] Active IPs: {len(counter)}, IPs: {list(counter.keys())}")
            if len(counter) == 0:
                continue

            # Calculate the expected frequency of SYN packets
            total_syn_packets = sum(counter.values())
            expected_frequency = total_syn_packets / len(counter)

            # Calculate the observed frequency of SYN packets
            observed_frequencies = list(counter.values())
            chi_square = sum((observed_frequency - expected_frequency) ** 2 / expected_frequency for observed_frequency in observed_frequencies)

            # Send entropy data to the plot thread
            current_time_str = time.strftime("%H:%M:%S")
            entropy_queue.put((current_time_str, chi_square))

            print(f"[INFO] Chi-square: {chi_square}, Active IPs: {len(counter)}, IPs: {list(counter.keys())}")    

            # update the threshold as per the update method of the DynamicThreshold class
            global threshold
            threshold = dynamic_threshold.update(chi_square)
            print(f"[INFO] Threshold: {threshold}")

            # check if the chi-square is above the threshold and the number of active IPs is greater than the minimum active IPs
            if chi_square > threshold:
                print("[ALERT] Possible DDoS attack detected!")
                for ip, count in counter.items():
                    if count > THRESHOLD_SYN_COUNT and ip not in BLOCKED_IPS:
                        block_ip(ip)
                        BLOCKED_IPS.add(ip)

# func to block an IP using iptables
def block_ip(ip):
    print(f"{Fore.RED}[ACTION] Blocking IP: {ip}{Style.RESET_ALL}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    threading.Thread(target=unblock_ip, args=(ip,)).start()

# func to unblock an IP using iptables
def unblock_ip(ip):
    sleep_time = 30
    time.sleep(sleep_time)
    print(f"{Fore.GREEN}[ACTION] Unblocking IP: {ip}{Style.RESET_ALL}")
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    BLOCKED_IPS.remove(ip)

# packet handler func
def packet_handler(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # Check for SYN packet
        ip = packet[IP].src
        with lock:
            print(f"[INFO] Received SYN from {ip}")
            if ip in BLOCKED_IPS:
                print(f"[BLOCKED] Refusing connection from: {ip}")
            else:
                ip_syn_tracker[ip].append(time.time())

# start packet sniffing
def start_sniffer(interface="eth0"):
    print(f"[INFO] Starting packet sniffer on {interface}")
    sniff(iface=interface, filter="tcp", prn=packet_handler, store=False)

# func to plot the entropy live
def live_plot():
    global threshold
    plt.style.use('ggplot')
    fig, ax = plt.subplots()
    entropies = []
    timestamps = []

    # update the polt to keep the live plot updated
    def update(frame):
        while not entropy_queue.empty():
            current_time, entropy = entropy_queue.get()
            timestamps.append(current_time)
            entropies.append(entropy)

            # Keep only the latest 20 points for plotting
            if len(entropies) > 20:
                entropies.pop(0)
                timestamps.pop(0)

        ax.clear()
        if ENTROPY == 1:
            ax.plot(timestamps, entropies, label="Entropy", marker='.', color='blue')
        elif CHI_SQUARE == 1:
            ax.plot(timestamps, entropies, label="Chi-square", marker='.', color='blue')
        
        ax.axhline(y=threshold, color='red', linestyle='--', label="Threshold")

        if ENTROPY == 1:
            ax.set_title("Live Entropy Monitoring")
        elif CHI_SQUARE == 1:
            ax.set_title("Live Chi-square Monitoring")
        
        ax.set_xlabel("Time")
        if ENTROPY == 1:
            ax.set_ylabel("Entropy")
        elif CHI_SQUARE == 1:
            ax.set_ylabel("Chi-Sqaure")
        ax.legend(loc="upper right")
        plt.xticks(rotation=45)
        plt.tight_layout()

    ani = FuncAnimation(fig, update, interval=MONITOR_INTERVAL * 1000)
    plt.show()

# main func
if __name__ == "__main__":
    # Start monitoring thread
    os.system(f"sudo iptables -F INPUT")
    if ENTROPY == 1:
        monitor_thread = threading.Thread(target=monitor_entropy, daemon=True)
        monitor_thread.start()
    elif CHI_SQUARE == 1:
        monitor_thread = threading.Thread(target=monitor_chi_square, daemon=True)
        monitor_thread.start()
    
    # Start live plotting thread
    plot_thread = threading.Thread(target=live_plot, daemon=True)
    plot_thread.start()

    # define the interfaces
    interface1 = "wlo1"
    interface2 = "lo"

    # threads for the packet sniffers
    thread1 = threading.Thread(target=start_sniffer, args=(interface1,))
    thread2 = threading.Thread(target=start_sniffer, args=(interface2,))

    thread1.start()
    thread2.start()

    # optionally, join the threads if you want to wait for them to finish
    thread1.join()
    thread2.join()
    plot_thread.join()
    monitor_thread.join()
    
