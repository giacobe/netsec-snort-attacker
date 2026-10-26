#!/usr/bin/env python3
import socket
import sys
import time
BROADCAST_IP = "10.0.0.255"
CONTROL_PORT = 9999
def send_control_msg(msg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(msg.encode(), (BROADCAST_IP, CONTROL_PORT))
def main():
    if len(sys.argv) > 1:
        flag = sys.argv[1].strip()
    else:
        flag = input("Enter the flag (e.g. payload_lastoctet_port): ").strip()
    # 2. Check the dynamically generated expected flag file from the hidden listener
    try:
        # Obfuscated location so students don't easily find it
        with open("/var/lib/urandom/.seed_auth", "r") as f:
            expected_flag = f.read().strip()
    except Exception:
        print("\n\033[93m[-] The attack has not fully registered yet! Please wait for the attacker to send ATTACK_INFO.\033[0m")
        return
    if flag == expected_flag: 
        print("\n\033[92m[+] Correct flag!\033[0m")
        print("\033[92m[+] You successfully performed Incident Response. Halting attack...\033[0m")
        send_control_msg("STOP")
    else:
        print("\n\033[91m[-] Incorrect flag!\033[0m")
        print("\033[91m[-] The Attacker noticed your probing! They have become stealthier and adapted the attack!\033[0m")
        send_control_msg("DELAY|5")
if __name__ == "__main__":
    main()
