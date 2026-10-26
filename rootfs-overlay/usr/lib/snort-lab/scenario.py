#!/usr/bin/env python3
"""PolyLinux-compatible deterministic scenario contract for snort-v1."""
import datetime as dt
import hashlib
import re

LAB_ID = "polymorphic-snort-1"
SYSTEM_PASSWORD = "snortSystemV1"
LEVEL_PASSWORD_ROOT = "snortStageV1-"
KEYWORDS = ("amber", "cedar", "falcon", "lantern", "marble", "orbit", "quartz", "willow")

def _cmdline():
    values = {}
    for item in open("/proc/cmdline", encoding="utf-8").read().split():
        if "=" in item:
            key, value = item.split("=", 1); values[key] = value
    return values

def encode_date(date): return format(int(date.strftime("%Y%m%d")), "X")

def identity():
    values = _cmdline()
    try:
        email = bytes.fromhex(values["polylab_email_hex"]).decode("utf-8").strip().lower()
        date = dt.datetime.strptime(values["polylab_date"], "%Y-%m-%d").date()
    except (KeyError, ValueError, UnicodeError) as error:
        raise RuntimeError("Missing or invalid PolyLab identity on the kernel command line") from error
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): raise RuntimeError("Invalid normalized PolyLab email")
    code = values.get("polylab_code", "").upper()
    if code != encode_date(date): raise RuntimeError("Exercise code does not match the PolyLab date")
    return email, date, code

def stage_seed(stage):
    email, date, _ = identity()
    fields = ("polylinux-seed-v1", LAB_ID, email, date.isoformat(), SYSTEM_PASSWORD,
              LEVEL_PASSWORD_ROOT + str(stage), str(stage))
    return hashlib.sha256(b"".join(value.encode() + b"\0" for value in fields)).digest()

def derive(stage, label, length=32): return hashlib.sha256(stage_seed(stage) + label.encode() + b"\0").digest()[:length]
def number(stage, label, minimum, maximum): return minimum + int.from_bytes(derive(stage, label, 8), "big") % (maximum - minimum + 1)

def stage_values(stage):
    if stage == 1:
        return {"stage": 1, "source_ip": "10.0.0.%d" % number(1, "source-ip", 100, 139),
                "destination_port": (2200, 3306, 5353, 8080, 8443)[number(1, "port-index", 0, 4)],
                "keyword": KEYWORDS[number(1, "keyword-index", 0, len(KEYWORDS) - 1)]}
    if stage == 2:
        return {"stage": 2, "source_ip": "10.0.0.%d" % number(2, "source-ip", 140, 179),
                "destination_port": 84, "community_sid": 24265,
                "community_message": "MALWARE-OTHER Malicious UA detected on non-standard port"}
    if stage == 3:
        return {"stage": 3, "source_ip": "10.0.0.%d" % number(3, "source-ip", 180, 219),
                "destination_port": (4444, 5555, 6666, 7777, 8888)[number(3, "port-index", 0, 4)],
                "marker": derive(3, "hex-marker", 8)}
    raise ValueError("stage must be 1, 2, or 3")

def noise_addresses():
    start = number(1, "noise-address-start", 30, 69)
    return ["10.0.0.%d" % (30 + ((start - 30 + offset * 7) % 50)) for offset in range(5)]

