from scapy.all import *
import pandas as pd
import time
import os
from datetime import datetime

# Initialize the networks dataframe to store the SSID, MAC address, signal strength, and timestamp
networks = pd.DataFrame(columns=["Timestamp", "SSID", "BSSID", "Signal Strength (dBm)", "Signal Strength (%)"])

# Function to convert signal strength (dBm) to percentage
def signal_strength_percent(dBm):
    if dBm == "N/A":
        return "N/A"
    try:
        # The typical range is from -100 dBm (very weak) to -30 dBm (strong)
        signal = int(dBm)
        if signal == "N/A":
            return "N/A"
        return max(0, min(100, int((signal + 100) * 2)))
    except:
        return "N/A"

# Callback function to process sniffed packets
def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # Extract relevant information from the packet
        ssid = packet[Dot11Elt].info.decode()  # SSID of the network
        bssid = packet[Dot11].addr2  # BSSID (MAC address)
        
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        
        # Get the timestamp when the packet was captured
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Convert signal strength to percentage
        signal_percent = signal_strength_percent(dbm_signal)

        # Add the network data to the DataFrame
        networks.loc[bssid] = [timestamp, ssid, bssid, dbm_signal, signal_percent]

# Function to save the networks data to a CSV file
def save_to_csv():
    # Save the data to a CSV file
    networks.to_csv("wifi_networks.csv", index=False)
    print("Networks information saved to wifi_networks.csv")

# Main function to start the sniffing process and save data
def main():
    # Start sniffing packets
    print("Starting to sniff for networks...")
    sniff(prn=callback, count=100)  # Capture 100 packets (you can increase this number)

    # After sniffing, save the data to CSV
    save_to_csv()

if __name__ == "__main__":
    main()
