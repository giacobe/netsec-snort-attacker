#!/usr/bin/env python3
"""Deterministic three-stage intrusion generator."""
import os, socket, sys, threading, time
sys.path.insert(0, "/usr/lib/snort-lab")
from scenario import identity, stage_values

DEFENDER, CONTROL_PORT = "10.0.0.10", 9999
state = {"stage": 1, "running": True, "delay": 1.0}
lock = threading.Lock()

def configure(address):
    while os.system("ip link show eth0 >/dev/null 2>&1") != 0: time.sleep(1)
    os.system("ip link set eth0 up && ip addr flush dev eth0 && ip addr add %s/24 dev eth0" % address)

def controls():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", CONTROL_PORT))
    while True:
        message = sock.recvfrom(256)[0].decode("ascii", "ignore").strip()
        with lock:
            if message.startswith("STAGE|") and message[-1:] in "123":
                state.update(stage=int(message[-1]), running=True, delay=1.0)
            elif message == "STOP": state["running"] = False
            elif message.startswith("DELAY|"):
                try: state["delay"] = max(1.0, min(10.0, float(message.split("|", 1)[1])))
                except ValueError: pass

def send_udp(values, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.sendto(payload, (DEFENDER, values["destination_port"])); sock.close()

def send_http():
    request = ("GET /telemetry/status HTTP/1.1\r\nHost: defender.local\r\n"
               "User-Agent: Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)\r\nConnection: close\r\n\r\n").encode()
    try:
        sock = socket.create_connection((DEFENDER, 84), timeout=2); sock.sendall(request); sock.close()
    except OSError: pass

def main():
    email, date, code = identity(); print("[*] Exercise %s for %s (%s)" % (code, email, date.isoformat()))
    threading.Thread(target=controls, daemon=True).start()
    configured = None; sequence = 0
    while True:
        with lock: stage, running, delay = state["stage"], state["running"], state["delay"]
        values = stage_values(stage)
        if configured != values["source_ip"]:
            configure(values["source_ip"]); configured = values["source_ip"]
        if running:
            if stage == 1: send_udp(values, ("SEQ:%d %s" % (sequence, values["keyword"])).encode())
            elif stage == 2: send_http()
            else: send_udp(values, b"telemetry:" + values["marker"] + b":complete")
            sequence += 1
        time.sleep(max(0.4, delay))

if __name__ == "__main__": main()
