import customtkinter as ctk
import requests
import pandas as pd
from tkinter import messagebox

# Set up the modern dark theme for the UI
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class TIPDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("TIP Aggregator - Security Operations")
        self.geometry("700x620")
        
        # --- UI Elements ---
        self.api_key_label = ctk.CTkLabel(self, text="VirusTotal API Key (v3):", font=("Roboto", 14, "bold"))
        self.api_key_label.pack(pady=(20, 5), padx=20, anchor="w")
        
        self.api_key_entry = ctk.CTkEntry(self, width=660, placeholder_text="Enter your VT API Key", show="*")
        self.api_key_entry.pack(pady=5, padx=20)
        
        self.ip_label = ctk.CTkLabel(self, text="Target IP Address:", font=("Roboto", 14, "bold"))
        self.ip_label.pack(pady=(10, 5), padx=20, anchor="w")
        
        self.ip_entry = ctk.CTkEntry(self, width=660, placeholder_text="e.g. 8.8.8.8")
        self.ip_entry.pack(pady=5, padx=20)
        
        # Scan Button
        self.scan_btn = ctk.CTkButton(self, text="Analyze IP", command=self.scan_ip, fg_color="#E74C3C", hover_color="#C0392B", font=("Roboto", 14, "bold"))
        self.scan_btn.pack(pady=20)
        
        # Results Output Area
        self.results_box = ctk.CTkTextbox(self, width=660, height=350, font=("Consolas", 13))
        self.results_box.pack(pady=10, padx=20)
        
    def scan_ip(self):
        api_key = self.api_key_entry.get().strip()
        ip_address = self.ip_entry.get().strip()
        
        if not api_key or not ip_address:
            messagebox.showerror("Input Error", "Please provide both an API Key and an IP Address.")
            return
            
        # Clear previous results and update UI
        self.results_box.delete("1.0", ctk.END)
        self.results_box.insert(ctk.END, f"[*] Querying VirusTotal v3 API for {ip_address}...\n\n")
        self.update()
        
        # VirusTotal v3 IP address endpoint
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        try:
            # Make the API request
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                self.parse_and_display(data)
            elif response.status_code == 401:
                self.results_box.insert(ctk.END, "[!] Error: Invalid API Key. Please verify your VirusTotal key.")
            elif response.status_code == 404:
                self.results_box.insert(ctk.END, "[!] Error: IP not found in VirusTotal dataset.")
            else:
                self.results_box.insert(ctk.END, f"[!] HTTP Error {response.status_code}: {response.text}")
                
        except Exception as e:
            self.results_box.insert(ctk.END, f"[!] Connection error: {str(e)}")
            
    def parse_and_display(self, data):
        try:
            attrs = data.get("data", {}).get("attributes", {})
            
            # Extract basic intelligence
            owner = attrs.get("as_owner", "Unknown")
            country = attrs.get("country", "Unknown")
            network = attrs.get("network", "Unknown")
            
            # Extract detection statistics
            stats = attrs.get("last_analysis_stats", {})
            
            # Extract individual engine results
            results = attrs.get("last_analysis_results", {})
            engine_data = []
            
            # Filter only the engines that flagged the IP as malicious or suspicious
            for engine, details in results.items():
                if details.get("category") in ["malicious", "suspicious"]:
                    engine_data.append({
                        "Security Engine": engine, 
                        "Category": details.get("category").upper(), 
                        "Result": details.get("result")
                    })
            
            # Use Pandas to create a clean tabular structure for the malicious hits
            df = pd.DataFrame(engine_data)
            
            # Build the text report
            report = "--- 🌐 IP INTELLIGENCE REPORT ---\n"
            report += f"Owner:   {owner}\n"
            report += f"Country: {country}\n"
            report += f"Network: {network}\n\n"
            
            report += "--- 📊 ANALYSIS STATS ---\n"
            report += f"🔴 Malicious:  {stats.get('malicious', 0)}\n"
            report += f"🟠 Suspicious: {stats.get('suspicious', 0)}\n"
            report += f"🟢 Harmless:   {stats.get('harmless', 0)}\n"
            report += f"⚪ Undetected: {stats.get('undetected', 0)}\n\n"
            
            report += "--- 🚨 THREAT DETECTIONS ---\n"
            if not df.empty:
                # Convert the DataFrame to a clean string format for the text box
                report += df.to_string(index=False)
            else:
                report += "[+] CLEAN: No malicious detections found by any security engine.\n"
                
            self.results_box.insert(ctk.END, report)
            
        except Exception as e:
            self.results_box.insert(ctk.END, f"[!] Error parsing JSON data: {str(e)}")

if __name__ == "__main__":
    app = TIPDashboard()
    app.mainloop()