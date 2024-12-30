# app.py

import streamlit as st
from scans import syn_scan, tcp_connect_scan, udp_scan
from utils.validation import (
    is_valid_ip,
    is_valid_hostname,
    strip_protocol,
    remove_trailing_slash
)
from port_info import port_info
import pandas as pd

def main():
    st.title("Website Vulnerabilities Checker")

    # User Input for Target
    target_url = st.text_input("Enter the target URL or IP address:")

    # Scan Type Selection
    st.subheader("Select Scan Types")
    scan_options = []
    syn_scan_option = st.checkbox("SYN Scan")
    tcp_connect_scan_option = st.checkbox("TCP Connect Scan")
    udp_scan_option = st.checkbox("UDP Scan")

    if syn_scan_option:
        scan_options.append("SYN")
    if tcp_connect_scan_option:
        scan_options.append("TCP Connect")
    if udp_scan_option:
        scan_options.append("UDP")

    # Custom Ports Input
    custom_ports_input = st.text_input("Enter custom ports separated by commas (leave blank for default):")

    # Start Scan Button
    if st.button("Start Scan"):
        target = strip_protocol(target_url)
        target = remove_trailing_slash(target)

        if not (is_valid_ip(target) or is_valid_hostname(target)):
            st.error("Invalid target URL or IP address.")
            return

        # Ports Configuration
        if custom_ports_input:
            try:
                ports = [int(port.strip()) for port in custom_ports_input.split(',') if port.strip().isdigit()]
                udp_ports = ports
            except ValueError:
                st.error("Please enter valid port numbers.")
                return
        else:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
                     8080, 8443]
            udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514,
                         520, 1701, 1812, 1813, 4500]

        # Real-time Progress Indicator
        progress_bar = st.progress(0)
        status_text = st.empty()

        results = []
        total_scans = len(scan_options)
        scan_counter = 0

        # Function to update progress
        def update_progress(current, total):
            progress = int(((scan_counter - 1) / total_scans + current / (total * total_scans)) * 100)
            progress_bar.progress(progress)

        # Performing Scans
        if "SYN" in scan_options:
            scan_counter += 1
            status_text.text("Performing SYN Scan...")
            syn_results = syn_scan(target, ports, progress_callback=update_progress)
            results.extend(syn_results)

        if "TCP Connect" in scan_options:
            scan_counter += 1
            status_text.text("Performing TCP Connect Scan...")
            tcp_results = tcp_connect_scan(target, ports, progress_callback=update_progress)
            results.extend(tcp_results)

        if "UDP" in scan_options:
            scan_counter += 1
            status_text.text("Performing UDP Scan...")
            udp_results = udp_scan(target, udp_ports, progress_callback=update_progress)
            results.extend(udp_results)

        progress_bar.progress(100)
        status_text.text("Scan completed.")

        # Display of Scan Results
        if results:
            df = pd.DataFrame(results)
            df = df[['port', 'protocol', 'status', 'service', 'vulnerabilities', 'attack_methods', 'prevention','real-worldexample','commonServices','misconfigurations','securityfeatures']]
            st.subheader("Scan Results")
            st.dataframe(df)

            # Export Functionality
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Results as CSV",
                data=csv,
                file_name='scan_results.csv',
                mime='text/csv'
            )
        else:
            st.info("No open ports found.")

if __name__ == "__main__":
    main()