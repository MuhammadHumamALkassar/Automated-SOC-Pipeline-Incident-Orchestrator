import requests
from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv

# 1. Load environment variables
load_dotenv("secrets.env")

# 2. Get variables with a fallback check
DISCORD_WEBHOOK_URL = os.getenv("WEBHOOK")
VT_API_KEY = os.getenv("VT_API_KEY")

# --- CRITICAL CHECK ---
if not DISCORD_WEBHOOK_URL or not VT_API_KEY:
    print("[!] WARNING: API Keys or Webhook URL not found in .env file!")
    print(f"DEBUG: WEBHOOK found: {bool(DISCORD_WEBHOOK_URL)}")
    print(f"DEBUG: VT_API_KEY found: {bool(VT_API_KEY)}")

app = Flask(__name__)

# --- FUNCTIONS ---

def check_virustotal(ip_address):
    """Checks IP reputation on VirusTotal"""
    if not VT_API_KEY:
        return 0
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0)
    except Exception as e:
        print(f"[!] Error checking VT: {e}")
    return 0

def send_discord_alert(ip, user, count, vt_score):
    """Sends a professional security alert card to Discord"""
    if not DISCORD_WEBHOOK_URL:
        print("[!] Cannot send alert: DISCORD_WEBHOOK_URL is missing!")
        return

    color = 15158332 if vt_score > 0 else 15105570
    
    payload = {
        "username": "SOC Orchestrator",
        "embeds": [{
            "title": "🚨 BRUTE FORCE ALERT 🚨",
            "color": color,
            "fields": [
                {"name": "Attacker IP", "value": f"`{ip}`", "inline": True},
                {"name": "Target User", "value": f"`{user}`", "inline": True},
                {"name": "Failures", "value": str(count), "inline": True},
                {"name": "VirusTotal Score", "value": f"{vt_score}/90 Malicious", "inline": False}
            ],
            "footer": {"text": "Security Automation Pipeline | 2026"}
        }]
    }

    try:
        r = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if r.status_code == 204:
            print("[-] Discord alert sent successfully.")
        else:
            print(f"[!] Discord returned error: {r.status_code}")
    except Exception as e:
        print(f"[!] Failed to send Discord alert: {e}")

# --- MAIN SERVER ---

@app.route('/webhook', methods=['POST'])
def splunk_alert():
    data = request.json
    if data and 'result' in data:
        src_ip = data['result'].get('src_ip', 'Unknown IP')
        user = data['result'].get('user', 'Unknown User')
        count = data['result'].get('failure_count', 0)
        
        print(f"\n[+] Alert Received. IP: {src_ip} | User: {user}")
        
        vt_score = check_virustotal(src_ip)
        print(f"[+] VirusTotal Score: {vt_score}")
        
        send_discord_alert(src_ip, user, count, vt_score)
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "error", "message": "Invalid data"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)