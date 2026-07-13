from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import time
import sqlite3
from collections import defaultdict, deque


# ============================================================
# CONFIGURATION
# ============================================================

PORT_SCAN_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW = 10

FLOOD_THRESHOLD = 50
FLOOD_TIME_WINDOW = 10


# ============================================================
# DATABASE SETUP
# ============================================================

DB_NAME = "packet_logs.db"


def initialize_database():
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    # Create table for captured packets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            protocol TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port TEXT,
            destination_port TEXT,
            packet_length INTEGER,
            tcp_flags TEXT
        )
    """)

    # Create table for security alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            source_ip TEXT,
            details TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_packet_to_database(
    timestamp,
    protocol,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    packet_length,
    tcp_flags
):
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO packets (
            timestamp,
            protocol,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            packet_length,
            tcp_flags
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        protocol,
        source_ip,
        destination_ip,
        str(source_port),
        str(destination_port),
        packet_length,
        str(tcp_flags)
    ))

    connection.commit()
    connection.close()


def save_alert_to_database(
    alert_type,
    source_ip,
    details
):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            alert_type,
            source_ip,
            details
        )
        VALUES (?, ?, ?, ?)
    """, (
        timestamp,
        alert_type,
        source_ip,
        details
    ))

    connection.commit()
    connection.close()


# ============================================================
# TRACKING DATA
# ============================================================

port_scan_tracker = defaultdict(lambda: deque())
flood_tracker = defaultdict(lambda: deque())

port_scan_alerted = set()
flood_alerted = set()


# ============================================================
# PORT SCAN DETECTION
# ============================================================

def detect_port_scan(source_ip, destination_port):
    current_time = time.time()

    port_scan_tracker[source_ip].append(
        (current_time, destination_port)
    )

    while (
        port_scan_tracker[source_ip]
        and current_time - port_scan_tracker[source_ip][0][0]
        > PORT_SCAN_TIME_WINDOW
    ):
        port_scan_tracker[source_ip].popleft()

    unique_ports = {
        port
        for _, port in port_scan_tracker[source_ip]
    }

    if (
        len(unique_ports) >= PORT_SCAN_THRESHOLD
        and source_ip not in port_scan_alerted
    ):
        details = (
            f"{len(unique_ports)} unique ports scanned "
            f"within {PORT_SCAN_TIME_WINDOW} seconds"
        )

        print("\n" + "!" * 65)
        print("⚠️ ALERT: POSSIBLE PORT SCAN DETECTED!")
        print(f"Source IP: {source_ip}")
        print(
            f"Unique ports scanned: {len(unique_ports)} "
            f"within {PORT_SCAN_TIME_WINDOW} seconds"
        )
        print("!" * 65)

        save_alert_to_database(
            "PORT SCAN",
            source_ip,
            details
        )

        port_scan_alerted.add(source_ip)


# ============================================================
# PACKET FLOOD DETECTION
# ============================================================

def detect_packet_flood(source_ip):
    current_time = time.time()

    flood_tracker[source_ip].append(current_time)

    while (
        flood_tracker[source_ip]
        and current_time - flood_tracker[source_ip][0]
        > FLOOD_TIME_WINDOW
    ):
        flood_tracker[source_ip].popleft()

    packet_count = len(flood_tracker[source_ip])

    if (
        packet_count >= FLOOD_THRESHOLD
        and source_ip not in flood_alerted
    ):
        details = (
            f"{packet_count} packets detected "
            f"within {FLOOD_TIME_WINDOW} seconds"
        )

        print("\n" + "!" * 65)
        print("⚠️ ALERT: POSSIBLE PACKET FLOOD DETECTED!")
        print(f"Source IP: {source_ip}")
        print(
            f"Packets detected: {packet_count} "
            f"within {FLOOD_TIME_WINDOW} seconds"
        )
        print("!" * 65)

        save_alert_to_database(
            "PACKET FLOOD",
            source_ip,
            details
        )

        flood_alerted.add(source_ip)


# ============================================================
# PACKET ANALYSIS
# ============================================================

def analyze_packet(packet):

    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "OTHER"
    source_port = "N/A"
    destination_port = "N/A"
    tcp_flags = "N/A"

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    packet_length = len(packet)

    print("\n" + "=" * 65)
    print(f"Timestamp        : {timestamp}")
    print(f"Protocol         : {protocol}")
    print(f"Source IP        : {source_ip}")
    print(f"Destination IP   : {destination_ip}")
    print(f"Source Port      : {source_port}")
    print(f"Destination Port : {destination_port}")
    print(f"Packet Length    : {packet_length} bytes")
    print(f"TCP Flags        : {tcp_flags}")
    print("=" * 65)

    # Save captured packet into SQLite database
    save_packet_to_database(
        timestamp,
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        packet_length,
        tcp_flags
    )

    # Check for packet flooding
    detect_packet_flood(source_ip)

    # Port scan detection applies to TCP packets
    if protocol == "TCP":
        detect_port_scan(source_ip, destination_port)


# ============================================================
# LIVE PACKET SNIFFER
# ============================================================

def run_live_sniffer():

    print("\n" + "=" * 65)
    print("       NETWORK PACKET SNIFFER WITH ALERT SYSTEM")
    print("=" * 65)
    print("Monitoring live network traffic...")
    print("Press Ctrl+C to stop.")
    print("=" * 65)

    try:
        sniff(
            prn=analyze_packet,
            store=False,
            promisc=False
        )

    except KeyboardInterrupt:
        print("\n" + "=" * 65)
        print("Packet capture stopped by user.")
        print("=" * 65)


# ============================================================
# BUILT-IN PORT SCAN ALERT TEST
# ============================================================

def run_alert_test():

    test_source_ip = "192.168.1.100"

    # Clear previous test data so the test can run repeatedly
    port_scan_tracker[test_source_ip].clear()
    port_scan_alerted.discard(test_source_ip)

    print("\n" + "=" * 65)
    print("RUNNING BUILT-IN PORT SCAN ALERT TEST")
    print("=" * 65)

    print(
        f"Simulating connections from {test_source_ip} "
        f"to multiple ports..."
    )

    for port in range(5001, 5011):

        print(
            f"Test connection attempt from "
            f"{test_source_ip} to port {port}"
        )

        detect_port_scan(test_source_ip, port)

    print("\n" + "=" * 65)
    print("Alert test completed.")
    print("=" * 65)


# ============================================================
# BUILT-IN PACKET FLOOD ALERT TEST
# ============================================================

def run_flood_test():

    test_source_ip = "192.168.1.200"

    # Clear previous test data so the test can run repeatedly
    flood_tracker[test_source_ip].clear()
    flood_alerted.discard(test_source_ip)

    print("\n" + "=" * 65)
    print("RUNNING BUILT-IN PACKET FLOOD ALERT TEST")
    print("=" * 65)

    print(
        f"Simulating rapid packet traffic from "
        f"{test_source_ip}..."
    )

    for packet_number in range(1, 51):

        detect_packet_flood(test_source_ip)

        if packet_number % 10 == 0:
            print(
                f"Simulated {packet_number} packets "
                f"from {test_source_ip}"
            )

    print("\n" + "=" * 65)
    print("Packet flood alert test completed.")
    print("=" * 65)


# ============================================================
# MAIN MENU
# ============================================================

def main():

    # Create SQLite database tables if needed
    initialize_database()

    print("\n" + "=" * 65)
    print("       NETWORK PACKET SNIFFER WITH ALERT SYSTEM")
    print("=" * 65)

    print("1. Start Live Packet Sniffer")
    print("2. Run Port Scan Alert Test")
    print("3. Run Packet Flood Alert Test")

    choice = input("\nEnter your choice (1, 2 or 3): ")

    if choice == "1":
        run_live_sniffer()

    elif choice == "2":
        run_alert_test()

    elif choice == "3":
        run_flood_test()

    else:
        print("Invalid choice. Please enter 1, 2 or 3.")


if __name__ == "__main__":
    main()