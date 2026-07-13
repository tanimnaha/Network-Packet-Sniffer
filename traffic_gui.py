import tkinter as tk
from tkinter import ttk
import sqlite3
from collections import Counter
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DB_NAME = "packet_logs.db"


# ============================================================
# TRAFFIC MONITOR GUI
# ============================================================

class TrafficMonitorGUI:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Network Packet Sniffer - Live Traffic Monitor"
        )

        self.root.geometry("1100x800")

        # ====================================================
        # MAIN TITLE
        # ====================================================

        title = tk.Label(
            root,
            text="NETWORK PACKET SNIFFER WITH LIVE TRAFFIC GRAPH",
            font=("Arial", 18, "bold")
        )

        title.pack(pady=15)


        # ====================================================
        # STATUS LABEL
        # ====================================================

        self.status_label = tk.Label(
            root,
            text="Monitoring SQLite packet database...",
            font=("Arial", 12)
        )

        self.status_label.pack(pady=5)


        # ====================================================
        # STATISTICS FRAME
        # ====================================================

        stats_frame = tk.Frame(root)

        stats_frame.pack(pady=10)


        self.total_label = tk.Label(
            stats_frame,
            text="Total Packets: 0",
            font=("Arial", 14, "bold")
        )

        self.total_label.pack(
            side=tk.LEFT,
            padx=30
        )


        self.tcp_label = tk.Label(
            stats_frame,
            text="TCP: 0",
            font=("Arial", 14, "bold")
        )

        self.tcp_label.pack(
            side=tk.LEFT,
            padx=30
        )


        self.udp_label = tk.Label(
            stats_frame,
            text="UDP: 0",
            font=("Arial", 14, "bold")
        )

        self.udp_label.pack(
            side=tk.LEFT,
            padx=30
        )


        # ====================================================
        # CREATE GRAPH
        # ====================================================

        self.figure = Figure(
            figsize=(9, 4),
            dpi=100
        )

        self.ax = self.figure.add_subplot(111)


        self.canvas = FigureCanvasTkAgg(
            self.figure,
            master=root
        )

        self.canvas.get_tk_widget().pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=10
        )


        # ====================================================
        # SECURITY ALERTS SECTION
        # ====================================================

        alerts_title = tk.Label(
            root,
            text="SECURITY ALERTS",
            font=("Arial", 15, "bold")
        )

        alerts_title.pack(pady=(10, 5))


        # Frame containing alert table
        alerts_frame = tk.Frame(root)

        alerts_frame.pack(
            fill=tk.BOTH,
            padx=20,
            pady=5
        )


        # Create alert table
        columns = (
            "timestamp",
            "alert_type",
            "source_ip",
            "details"
        )


        self.alert_tree = ttk.Treeview(
            alerts_frame,
            columns=columns,
            show="headings",
            height=5
        )


        # Table headings
        self.alert_tree.heading(
            "timestamp",
            text="Timestamp"
        )

        self.alert_tree.heading(
            "alert_type",
            text="Alert Type"
        )

        self.alert_tree.heading(
            "source_ip",
            text="Source IP"
        )

        self.alert_tree.heading(
            "details",
            text="Details"
        )


        # Column widths
        self.alert_tree.column(
            "timestamp",
            width=170
        )

        self.alert_tree.column(
            "alert_type",
            width=140
        )

        self.alert_tree.column(
            "source_ip",
            width=150
        )

        self.alert_tree.column(
            "details",
            width=450
        )


        self.alert_tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )


        # Scrollbar for alert table
        scrollbar = ttk.Scrollbar(
            alerts_frame,
            orient=tk.VERTICAL,
            command=self.alert_tree.yview
        )

        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )


        self.alert_tree.configure(
            yscrollcommand=scrollbar.set
        )


        # ====================================================
        # REFRESH BUTTON
        # ====================================================

        refresh_button = ttk.Button(
            root,
            text="Refresh Now",
            command=self.refresh_dashboard
        )

        refresh_button.pack(pady=10)


        # Start automatic updates
        self.refresh_dashboard()


    # ========================================================
    # GET PACKET DATA
    # ========================================================

    def get_packet_data(self):

        try:

            connection = sqlite3.connect(DB_NAME)

            cursor = connection.cursor()


            cursor.execute(
                "SELECT protocol FROM packets"
            )

            rows = cursor.fetchall()


            connection.close()


            protocols = [
                row[0]
                for row in rows
            ]


            return protocols


        except sqlite3.Error as error:

            self.status_label.config(
                text=f"Database error: {error}"
            )

            return []


    # ========================================================
    # GET SECURITY ALERTS
    # ========================================================

    def get_alert_data(self):

        try:

            connection = sqlite3.connect(DB_NAME)

            cursor = connection.cursor()


            cursor.execute("""
                SELECT
                    timestamp,
                    alert_type,
                    source_ip,
                    details
                FROM alerts
                ORDER BY id DESC
                LIMIT 20
            """)


            rows = cursor.fetchall()


            connection.close()


            return rows


        except sqlite3.Error:

            return []


    # ========================================================
    # UPDATE GRAPH
    # ========================================================

    def update_graph(self):

        protocols = self.get_packet_data()


        protocol_counts = Counter(protocols)


        tcp_count = protocol_counts.get(
            "TCP",
            0
        )


        udp_count = protocol_counts.get(
            "UDP",
            0
        )


        other_count = sum(
            count
            for protocol, count
            in protocol_counts.items()
            if protocol not in ["TCP", "UDP"]
        )


        total_packets = len(protocols)


        # Update statistics labels
        self.total_label.config(
            text=f"Total Packets: {total_packets}"
        )


        self.tcp_label.config(
            text=f"TCP: {tcp_count}"
        )


        self.udp_label.config(
            text=f"UDP: {udp_count}"
        )


        # Clear previous graph
        self.ax.clear()


        protocol_names = [
            "TCP",
            "UDP",
            "OTHER"
        ]


        packet_counts = [
            tcp_count,
            udp_count,
            other_count
        ]


        self.ax.bar(
            protocol_names,
            packet_counts
        )


        self.ax.set_title(
            "Live Network Traffic by Protocol"
        )


        self.ax.set_xlabel(
            "Protocol"
        )


        self.ax.set_ylabel(
            "Number of Packets"
        )


        self.ax.grid(
            axis="y",
            linestyle="--",
            alpha=0.5
        )


        self.figure.tight_layout()

        self.canvas.draw()


    # ========================================================
    # UPDATE SECURITY ALERT TABLE
    # ========================================================

    def update_alerts(self):

        # Remove old rows from GUI table
        for item in self.alert_tree.get_children():

            self.alert_tree.delete(item)


        # Get latest alerts from database
        alerts = self.get_alert_data()


        # Add alerts to GUI table
        for alert in alerts:

            self.alert_tree.insert(
                "",
                tk.END,
                values=alert
            )


    # ========================================================
    # REFRESH COMPLETE DASHBOARD
    # ========================================================

    def refresh_dashboard(self):

        self.update_graph()

        self.update_alerts()


        self.status_label.config(
            text="Live traffic graph and security alerts updated successfully."
        )


        # Automatically refresh every 2 seconds
        self.root.after(
            2000,
            self.refresh_dashboard
        )


# ============================================================
# START GUI APPLICATION
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = TrafficMonitorGUI(root)

    root.mainloop()