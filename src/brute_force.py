import socket
import time
import random
import datetime

# CONFIGURATION
SPLUNK_HOST = 'localhost'
SPLUNK_PORT = 1514

# SIMULATION PARAMETERS
ATTACKER_IPS = ['192.168.1.105', '10.0.0.15', '172.16.23.88', '203.0.113.42']
TARGET_USERS = ['admin', 'root', 'service_account', 'jdoe']
SUCCESS_RATE = 0.1  # 10% chance the attacker eventually guesses right

def send_log(message):
    """Sends a raw string message to Splunk via TCP."""
    try:
        # Create a socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SPLUNK_HOST, SPLUNK_PORT))
        
        # Send data (must be bytes)
        sock.sendall(message.encode('utf-8'))
        sock.close()
        print(f"[+] Sent: {message.strip()}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")

def generate_brute_force():
    """Simulates a brute force attack sequence."""
    
    # Pick a random attacker and target
    attacker_ip = random.choice(ATTACKER_IPS)
    target_user = random.choice(TARGET_USERS)
    
    # Randomize the number of failed attempts (between 5 and 20)
    num_failures = random.randint(5, 20)
    
    print(f"[*] Starting attack from {attacker_ip} targeting user '{target_user}'...")

    # 1. GENERATE FAILURES
    for _ in range(num_failures):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Format: key=value pairs for easy parsing in Splunk
        log_entry = f"{timestamp} event_type=ssh_failed src_ip={attacker_ip} user={target_user} reason='password check failed'\n"
        send_log(log_entry)
        time.sleep(random.uniform(0.1, 0.5))  # Fast attempts (machine speed)

    # 2. DECIDE IF SUCCESSFUL
    if random.random() < SUCCESS_RATE:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp} event_type=ssh_success src_ip={attacker_ip} user={target_user} reason='password accepted'\n"
        send_log(log_entry)
        print(f"[!] BREAKTHROUGH: {attacker_ip} successfully logged in as {target_user}!")

if __name__ == "__main__":
    print("--- Starting Traffic Generator ---")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            generate_brute_force()
            # Wait a bit between different "attackers"
            time.sleep(random.randint(5, 10))
    except KeyboardInterrupt:
        print("\nStopping generator.")