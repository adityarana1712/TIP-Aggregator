import customtkinter as ctk
from tkinter import ttk, messagebox
import requests
import threading

# Core UI Settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class RichTIPDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("TIP Aggregator Pro - SOC Dashboard")
        self.geometry("1000x700")
        
        # Configure grid layout (1 row, 2 columns)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR (Left Panel) ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ TIP Aggregator", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.api_key_label = ctk.CTkLabel(self.sidebar_frame, text="VirusTotal API Key:")
        self.api_key_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.api_key_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="Enter API Key...", show="*")
        self.api_key_entry.grid(row=2, column=0, padx=20, pady=(5, 20), sticky="ew")

        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_menu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Dark", "Light", "System"], command=self.change_appearance_mode)
        self.appearance_mode_menu.grid(row=6, column=0, padx=20, pady=(10, 20))

        # --- MAIN CONTENT AREA (Right Panel) ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Search Bar Area
        self.search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        self.search_frame.grid_columnconfigure(0, weight=1)

        self.ip_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Enter Target IP (e.g., 8.8.8.8)", height=40, font=ctk.CTkFont(size=14))
        self.ip_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.scan_btn = ctk.CTkButton(self.search_frame, text="Analyze IP", height=40, font=ctk.CTkFont(weight="bold"), fg_color="#E74C3C", hover_color="#C0392B", command=self.start_scan_thread)
        self.scan_btn.grid(row=0, column=1)

        self.progress_bar = ctk.CTkProgressBar(self.main_frame, mode="indeterminate")
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        self.progress_bar.set(0)

        # Metric Cards (Stats)
        self.metrics_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.metrics_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        self.metrics_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.malicious_card = self.create_metric_card(self.metrics_frame, "Malicious", "0", 0, "#E74C3C")
        self.suspicious_card = self.create_metric_card(self.metrics_frame, "Suspicious", "0", 1, "#F39C12")
        self.safe_card = self.create_metric_card(self.metrics_frame, "Harmless", "0", 2, "#2ECC71")
        self.owner_card = self.create_metric_card(self.metrics_frame, "Network Owner", "-", 3, "#3498DB")

        # Tab View for Data
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.grid(row=3, column=0, sticky="nsew")
        self.main_frame.grid_rowconfigure(3, weight=1)

        self.tabview.add("Threat Detections")
        self.tabview.add("Geographic Info")

        # Setup Treeview (Data Table) inside Tab 1
        self.setup_table()
        
        # Geolocation Labels in Tab 2
        self.geo_label = ctk.CTkLabel(self.tabview.tab("Geographic Info"), text="Awaiting Scan...", font=ctk.CTkFont(size=14))
        self.geo_label.pack(pady=20, padx=20, anchor="nw")

    def create_metric_card(self, parent, title, value, col, color):
        frame = ctk.CTkFrame(parent, corner_radius=10, border_width=2, border_color=color)
        frame.grid(row=0, column=col, sticky="ew", padx=5)
        
        title_lbl = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=12, weight="bold"))
        title_lbl.pack(pady=(10, 0))
        
        value_lbl = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=24, weight="bold"), text_color=color)
        value_lbl.pack(pady=(0, 10))
        return value_lbl

    def setup_table(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", rowheight=30, fieldbackground="#2b2b2b", borderwidth=0)
        style.map("Treeview", background=[("selected", "#1f538d")])
        style.configure("Treeview.Heading", background="#1f538d", foreground="white", font=("Roboto", 11, "bold"))

        self.tree = ttk.Treeview(self.tabview.tab("Threat Detections"), columns=("Engine", "Category", "Result"), show="headings")
        self.tree.heading("Engine", text="Security Engine")
        self.tree.heading("Category", text="Threat Category")
        self.tree.heading("Result", text="Detection Name")
        
        self.tree.column("Engine", width=150)
        self.tree.column("Category", width=100)
        self.tree.column("Result", width=300)
        
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def change_appearance_mode(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def start_scan_thread(self):
        api_key = self.api_key_entry.get().strip()
        ip_address = self.ip_entry.get().strip()
        
        if not api_key or not ip_address:
            messagebox.showerror("Input Error", "Please provide both an API Key and an IP Address.")
            return

        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.progress_bar.start()
        
        # Clear previous treeview data
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Run API request in a background thread to prevent GUI freezing
        thread = threading.Thread(target=self.fetch_api_data, args=(api_key, ip_address))
        thread.start()

    def fetch_api_data(self, api_key, ip_address):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"accept": "application/json", "x-apikey": api_key}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.after(0, self.update_gui, data)
            else:
                self.after(0, self.show_error, f"HTTP Error {response.status_code}: {response.text}")
        except Exception as e:
            self.after(0, self.show_error, f"Connection error: {str(e)}")

    def update_gui(self, data):
        self.progress_bar.stop()
        self.scan_btn.configure(state="normal", text="Analyze IP")
        
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        # Update Metric Cards
        self.malicious_card.configure(text=str(stats.get("malicious", 0)))
        self.suspicious_card.configure(text=str(stats.get("suspicious", 0)))
        self.safe_card.configure(text=str(stats.get("harmless", 0)))
        self.owner_card.configure(text=attrs.get("as_owner", "Unknown")[:15]) # Truncate long names

        # Update Geolocation Tab
        geo_text = f"Continent: {attrs.get('continent', 'Unknown')}\n"
        geo_text += f"Country: {attrs.get('country', 'Unknown')}\n"
        geo_text += f"Network Subnet: {attrs.get('network', 'Unknown')}\n"
        geo_text += f"Regional Internet Registry: {attrs.get('regional_internet_registry', 'Unknown')}"
        self.geo_label.configure(text=geo_text)

        # Populate Data Table
        results = attrs.get("last_analysis_results", {})
        flagged = False
        for engine, details in results.items():
            if details.get("category") in ["malicious", "suspicious"]:
                flagged = True
                self.tree.insert("", "end", values=(engine, details.get("category").upper(), details.get("result")))
        
        if not flagged:
            self.tree.insert("", "end", values=("No Detections", "CLEAN", "0 engines flagged this IP."))

    def show_error(self, message):
        self.progress_bar.stop()
        self.scan_btn.configure(state="normal", text="Analyze IP")
        messagebox.showerror("Scan Error", message)

if __name__ == "__main__":
    app = RichTIPDashboard()
    app.mainloop()