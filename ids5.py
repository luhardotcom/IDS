import tkinter as tk
from tkinter import messagebox, Scrollbar, Text, filedialog
from scapy.all import sniff, IP, TCP
from sklearn.ensemble import IsolationForest
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import joblib
import threading
import os
import nmap  # Nmap library for scanning

# Sample predefined signatures (example)
signatures = [
    b"malicious_string_1",
    b"malicious_string_2"
]

# Global variables
data = []
clf = None
scaler = MinMaxScaler()
captured_traffic = []
traffic_text = None

# Define the function to load the model
def load_model():
    global clf, scaler
    try:
        clf = joblib.load('trained_model.pkl')
        scaler = joblib.load('scaler.pkl')
        print("Model and scaler loaded successfully.")
    except FileNotFoundError:
        print("No pre-trained model found.")

def load_multiple_datasets():
    """Load and preprocess multiple datasets."""
    try:
        file_paths = filedialog.askopenfilenames(
            title="Select Dataset Files",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_paths:
            messagebox.showinfo("No Files Selected", "No dataset files were selected.")
            return

        combined_df = pd.DataFrame()
        for file_path in file_paths:
            df = pd.read_csv(file_path, header=None,low_memory=False)
            if df.shape[1] >= 42:  # Ensure the file has the expected number of columns
                df.columns = [
                    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
                    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
                    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
                    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
                ]
                
                features = df[['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent']]
                features['land'] = features['land'].apply(lambda x: 1 if x == 'yes' else 0)
                
                combined_df = pd.concat([combined_df, features], ignore_index=True)
        
        if combined_df.empty:
            messagebox.showwarning("Invalid Data", "No valid data found in selected files.")
            return

        # Normalize the data
        global scaler
        scaled_features = scaler.fit_transform(combined_df)
        normalized_df = pd.DataFrame(scaled_features, columns=combined_df.columns)
        normalized_df.to_csv('network_traffic_combined.csv', index=False)
        messagebox.showinfo("Datasets Loaded", "Multiple datasets have been combined and saved successfully.")
        print("Datasets loaded and combined.")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while loading datasets: {str(e)}")


def load_dataset():
    try:
        df = pd.read_csv('network_traffic_combined.csv')
        features = df.drop(columns=['label'], errors='ignore')
        return features
    except FileNotFoundError:
        print("Combined dataset not found.")
        return None


def preprocess_packet(packet):
    features = {
        "duration": 0,
        "src_bytes": len(packet),
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0
    }
    return pd.DataFrame([features])


def packet_callback(packet):
    global data, captured_traffic, traffic_text

    if packet.haslayer(TCP):
        if any(signature in bytes(packet[TCP].payload) for signature in signatures):
            messagebox.showinfo("Signature-Based Attack Detected", packet.summary())
        
        features = preprocess_packet(packet)
        data.append(features)

        traffic_summary = f"Source: {packet[IP].src} -> Dest: {packet[IP].dst}, Length: {len(packet)} bytes"
        captured_traffic.append(traffic_summary)

        if traffic_text:
            traffic_text.insert(tk.END, traffic_summary + "\n")
            traffic_text.see(tk.END)


def start_sniffing():
    print("Sniffing started...")
    sniff(prn=packet_callback, store=0, timeout=10)
    messagebox.showinfo("Packet Capture", "Packet capture completed.")


def train_anomaly_model():
    global clf, scaler
    features = load_dataset()
    if features is None:
        messagebox.showerror("Error", "Dataset not loaded!")
        return

    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(features)
    joblib.dump(clf, 'trained_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    print("Model trained and saved.")


def detect_anomalies():
    global clf, data, scaler
    if clf is None:
        messagebox.showerror("Error", "Model not trained!")
        return

    if not data:
        messagebox.showwarning("No Data", "No packet data available.")
        return

    combined_data = pd.concat(data, ignore_index=True)
    scaled_data = scaler.transform(combined_data)
    predictions = clf.predict(scaled_data)

    anomalies = combined_data[predictions == -1]
    if not anomalies.empty:
        messagebox.showinfo("Anomalies Detected", f"Anomalous packets:\n{anomalies.head()}")
    else:
        messagebox.showinfo("Normal Traffic", "No anomalies detected.")


def clear_traffic_display():
    global traffic_text
    traffic_text.delete(1.0, tk.END)


def perform_nmap_scan(target_ip):
    """Run an Nmap scan on a target IP and return the results."""
    nm = nmap.PortScanner()
    try:
        print(f"Scanning target {target_ip}...")
        nm.scan(target_ip, '22-1024')  # Scan ports 22-1024 (SSH, HTTP, etc.)

        # Access scan result
        host_info = nm[target_ip]

        # Display basic host information
        host_status = host_info.state()
        host_hostname = host_info.hostname() if 'hostnames' in host_info else 'Unknown'

        # Capture open ports
        open_ports = []
        if 'tcp' in host_info:
            for port in host_info['tcp']:
                state = host_info['tcp'][port]['state']
                if state == 'open':
                    open_ports.append(port)

        # Capture service version information (optional)
        service_versions = []
        for port in open_ports:
            service_info = host_info['tcp'][port]
            service_versions.append(f"Port {port}: {service_info['name']} (Version: {service_info.get('product', 'N/A')})")

        # Display the output
        output = f"Host: {target_ip} ({host_hostname})\n"
        output += f"Status: {host_status}\n"
        output += f"Open Ports: {', '.join(map(str, open_ports))}\n"

        if service_versions:
            output += f"Service Versions:\n" + "\n".join(service_versions)
        
        # Check for OS details if available
        if 'osmatch' in host_info:
            output += f"\nOperating System: {host_info['osmatch'][0]['name']}"

        messagebox.showinfo("Nmap Scan Result", output)

    except Exception as e:
        messagebox.showerror("Nmap Error", f"An error occurred: {e}")


def start_nmap_scan():
    target_ip = "192.168.1.1"  # Example target IP (can be modified)
    perform_nmap_scan(target_ip)


def start_gui():
    root = tk.Tk()
    root.title("Intrusion Detection System")
    root.geometry("700x600")

    load_model()  # Call the function to load the model

    def sniff_packets_thread():
        threading.Thread(target=start_sniffing, daemon=True).start()

    def detect_anomalies_thread():
        threading.Thread(target=detect_anomalies, daemon=True).start()

    def train_model_thread():
        threading.Thread(target=train_anomaly_model, daemon=True).start()

    # Buttons and UI elements
    tk.Button(root, text="Load Multiple Datasets", command=load_multiple_datasets, width=20, height=2).pack(pady=10)
    tk.Button(root, text="Start Packet Sniffing", command=sniff_packets_thread, width=20, height=2).pack(pady=10)
    tk.Button(root, text="Detect Anomalies", command=detect_anomalies_thread, width=20, height=2).pack(pady=10)
    tk.Button(root, text="Train Model", command=train_model_thread, width=20, height=2).pack(pady=10)
    tk.Button(root, text="Clear Traffic Display", command=clear_traffic_display, width=20, height=2).pack(pady=10)
    tk.Button(root, text="Start Nmap Scan", command=start_nmap_scan, width=20, height=2).pack(pady=10)

    traffic_text = Text(root, height=10, width=70)
    traffic_text.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    start_gui()
