import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from database import Database
from file_logger import FileLogger
from datetime import datetime
import threading


class IDSGUI:
    """Main window / dashboard for our little Python IDS"""

    def __init__(self, root):
        self.root = root
        self.root.title("Python IDS - Intrusion Detection System")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f0f0f0")

        # Connect to our storage bits
        self.db = Database()
        self.logger = FileLogger()

        self.is_monitoring = False

        self.create_widgets()

        # Load initial data so it doesn't look empty on startup
        self.refresh_threats()
        self.load_logs()
        self.update_statistics()  # IMPORTANT: update status bar stats on startup

    def create_widgets(self):
        """Build all the visual parts of the window"""

        # ──────────────── Top bar ────────────────
        header = tk.Frame(self.root, bg="#2c3e50", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🛡️ Python Intrusion Detection System",
            font=("Arial", 24, "bold"),
            bg="#2c3e50",
            fg="white"
        ).pack(pady=20)

        # ──────────────── Status strip ────────────────
        status_bar = tk.Frame(self.root, bg="#34495e", height=50)
        status_bar.pack(fill="x")
        status_bar.pack_propagate(False)

        self.status_label = tk.Label(
            status_bar,
            text="⚫ Status: Idle",
            font=("Arial", 12, "bold"),
            bg="#34495e",
            fg="#ecf0f1"
        )
        self.status_label.pack(side="left", padx=20, pady=10)

        self.stats_label = tk.Label(
            status_bar,
            text="📊 Threats: 0 | Blocked: 0",
            font=("Arial", 11),
            bg="#34495e",
            fg="#ecf0f1"
        )
        self.stats_label.pack(side="right", padx=20, pady=10)

        # ──────────────── Main area ────────────────
        main_area = tk.Frame(self.root, bg="#f0f0f0")
        main_area.pack(fill="both", expand=True, padx=10, pady=10)

        # Left side → threats list
        threats_panel = tk.LabelFrame(
            main_area,
            text="🚨 Detected Threats",
            font=("Arial", 12, "bold"),
            bg="#f0f0f0",
            fg="#2c3e50"
        )
        threats_panel.pack(side="left", fill="both", expand=True, padx=(0, 5))

        tree_container = tk.Frame(threats_panel, bg="#f0f0f0")
        tree_container.pack(fill="both", expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(tree_container)
        scrollbar.pack(side="right", fill="y")

        columns = ("IP Address", "Attempts", "Threat Level", "Timestamp", "Blocked")

        self.threat_tree = ttk.Treeview(
            tree_container,
            columns=columns,
            show="headings",
            yscrollcommand=scrollbar.set,
            height=15
        )
        scrollbar.config(command=self.threat_tree.yview)

        # Set sensible column widths
        widths = {"IP Address": 140, "Attempts": 80, "Threat Level": 100,
                  "Timestamp": 160, "Blocked": 70}

        for col in columns:
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=widths.get(col, 100))

        self.threat_tree.pack(fill="both", expand=True)

        # Color rows based on threat level
        self.threat_tree.tag_configure('CRITICAL', background='#e74c3c', foreground='white')
        self.threat_tree.tag_configure('HIGH',     background='#e67e22', foreground='white')
        self.threat_tree.tag_configure('MEDIUM',   background='#f39c12')
        self.threat_tree.tag_configure('LOW',      background='#f1c40f')

        # Right side → live log view
        log_panel = tk.LabelFrame(
            main_area,
            text="📋 Activity Logs",
            font=("Arial", 12, "bold"),
            bg="#f0f0f0",
            fg="#2c3e50"
        )
        log_panel.pack(side="right", fill="both", expand=True, padx=(5, 0))

        self.log_display = scrolledtext.ScrolledText(
            log_panel,
            height=20,
            width=45,
            font=("Courier", 9),
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="white"
        )
        self.log_display.pack(fill="both", expand=True, padx=5, pady=5)

        # ──────────────── Bottom buttons ────────────────
        btn_bar = tk.Frame(self.root, bg="#f0f0f0", height=70)
        btn_bar.pack(fill="x", padx=10, pady=(0, 10))
        btn_bar.pack_propagate(False)

        common_btn = {
            "font": ("Arial", 11, "bold"),
            "width": 15,
            "height": 2,
            "cursor": "hand2"
        }

        self.start_btn = tk.Button(
            btn_bar,
            text="▶️ Start Monitoring",
            bg="#27ae60",
            fg="white",
            command=self.start_monitoring,
            **common_btn
        )
        self.start_btn.pack(side="left", padx=5, pady=10)

        self.stop_btn = tk.Button(
            btn_bar,
            text="⏸️ Stop Monitoring",
            bg="#e74c3c",
            fg="white",
            command=self.stop_monitoring,
            state="disabled",
            **common_btn
        )
        self.stop_btn.pack(side="left", padx=5, pady=10)

        tk.Button(
            btn_bar, text="🔄 Refresh Data", bg="#3498db", fg="white",
            command=self.refresh_all, **common_btn
        ).pack(side="left", padx=5, pady=10)

        tk.Button(
            btn_bar, text="📊 Statistics", bg="#9b59b6", fg="white",
            command=self.show_statistics, **common_btn
        ).pack(side="left", padx=5, pady=10)

        tk.Button(
            btn_bar, text="🗑️ Clear Logs", bg="#95a5a6", fg="white",
            command=self.clear_logs, **common_btn
        ).pack(side="left", padx=5, pady=10)

        # ✅ Unblock button (correct placement + uses your existing style dict)
        tk.Button(
            btn_bar,
            text="🔓 Unblock IP",
            bg="#f39c12",
            fg="white",
            command=self.unblock_selected,
            **common_btn
        ).pack(side="left", padx=5, pady=10)

    def refresh_threats(self):
        """Pull latest threats from database and show them in the table"""
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)

        threats = self.db.get_all_threats(limit=100)

        for t in threats:
            # t = (id, ip, attempts, level, timestamp, blocked, notes?)
            ip = t[1]
            attempts = t[2]
            level = t[3]
            when = t[4][:19]          # cut off microseconds
            blocked = "Yes" if t[5] else "No"

            self.threat_tree.insert(
                "",
                "end",
                values=(ip, attempts, level, when, blocked),
                tags=(level,)
            )

    def load_logs(self):
        """Show the last bunch of log lines"""
        self.log_display.delete(1.0, tk.END)
        lines = self.logger.get_recent_logs(50)

        for line in lines:
            self.log_display.insert(tk.END, line)

        self.log_display.see(tk.END)

    def refresh_all(self):
        """Quick refresh everything button"""
        self.refresh_threats()
        self.load_logs()
        self.update_statistics()
        self.logger.log_system("Dashboard refreshed manually")

    def update_statistics(self):
        """Update the little stats line in the status bar"""
        stats = self.db.get_statistics()
        self.stats_label.config(
            text=f"📊 Threats: {stats['total_threats']} | Blocked: {stats['total_blocked']}"
        )

    def start_monitoring(self):
        self.is_monitoring = True
        self.status_label.config(text="🟢 Status: Monitoring Active", fg="#27ae60")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.logger.log_system("Monitoring started (via GUI)")
        messagebox.showinfo("Started", "IDS monitoring is now running!")

    def stop_monitoring(self):
        self.is_monitoring = False
        self.status_label.config(text="🔴 Status: Monitoring Stopped", fg="#e74c3c")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.logger.log_system("Monitoring stopped (via GUI)")
        messagebox.showinfo("Stopped", "Monitoring has been paused.")

    def show_statistics(self):
        """Popup with more detailed stats"""
        stats = self.db.get_statistics()

        win = tk.Toplevel(self.root)
        win.title("IDS Statistics")
        win.geometry("400x300")
        win.configure(bg="#f0f0f0")

        tk.Label(win, text="📊 System Statistics", font=("Arial", 16, "bold"),
                 bg="#f0f0f0").pack(pady=20)

        text = f"""
Total Threats Detected : {stats['total_threats']}
Total IPs Blocked      : {stats['total_blocked']}

Threats by level:
""" + "\n".join(f"  {lvl}: {cnt}" for lvl, cnt in stats.get('by_level', {}).items()) + f"""

Last updated: {datetime.now():%Y-%m-%d %H:%M:%S}
"""

        tk.Label(win, text=text, font=("Courier", 11), bg="#f0f0f0",
                 justify="left").pack(pady=10)

        tk.Button(win, text="Close", command=win.destroy,
                  bg="#3498db", fg="white", font=("Arial", 11),
                  width=15).pack(pady=20)

    def clear_logs(self):
        if messagebox.askyesno("Clear Logs", "Really clear the log view?"):
            self.log_display.delete(1.0, tk.END)
            self.logger.log_system("Log display was cleared")

    def unblock_selected(self):
        """Unblock selected IP from threat table"""
        from blocker import Blocker

        selected = self.threat_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an IP to unblock")
            return

        item = self.threat_tree.item(selected[0])
        ip = item["values"][0]  # IP Address column

        if messagebox.askyesno("Unblock IP", f"Unblock {ip}?"):
            blocker = Blocker()
            if blocker.unblock_ip(ip):
                self.logger.log_system(f"IP unblocked via GUI: {ip}")
                self.refresh_all()
                messagebox.showinfo("Success", f"Unblocked {ip}")
            else:
                messagebox.showerror("Error", f"Failed to unblock {ip}\nMay need sudo")


def run_gui():
    root = tk.Tk()
    app = IDSGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
