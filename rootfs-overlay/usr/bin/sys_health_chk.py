#!/usr/bin/env python3
import socket
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 8888))

while True:
    try:
        data, addr = sock.recvfrom(1024)
        msg = data.decode('utf-8').strip()
        if msg.startswith("ATTACK_INFO|"):
            parts = msg.split("|")
            if len(parts) == 4:
                _, attacker_ip, target_port, payload = parts
                
                # Save the required flag to an obfuscated file path
                last_octet = attacker_ip.split('.')[-1]
                expected_flag = f"{payload}_{last_octet}_{target_port}"
                
                # Ensure path exists just in case
                os.makedirs("/var/lib/urandom", exist_ok=True)
                with open("/var/lib/urandom/.seed_auth", "w") as f:
                    f.write(expected_flag)
                
                # Shut down the socket once the secret is stored
                sock.close()
                break
    except Exception as e:
        pass
