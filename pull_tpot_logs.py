# ==============================================================
# LIVE TPOT LOG EXTRACTOR – NO PACKET LIMIT
# SAFE PUBLIC VERSION (SECRETS EXTERNALIZED)
# ==============================================================

import os, json, time
import pandas as pd
import paramiko
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------
# LOAD SECRETS (NOT STORED IN GITHUB)
# --------------------------------------------------------------
with open("secrets.json", "r") as f:
    secrets = json.load(f)

AWS_IP = secrets["AWS_IP"]
AWS_USER = secrets["AWS_USER"]
AWS_PORT = secrets["AWS_PORT"]
PEM_PATH = secrets["PEM_PATH"]

REMOTE_BASE = "/home/ubuntu/tpotce/data"
LOCAL_BASE = secrets["LOCAL_BASE"]

LOOKBACK_HOURS = 24 * 30
ALLOWED_EXTENSIONS = (".log", ".json", ".txt")

HONEYPOT_NAMES = [
    "adbhoney", "conpot", "cowrie", "dicompot", "dionaea", "elasticpot",
    "fatt", "h0neytr4p", "heralding", "honeyaml", "honeytrap", "ipphoney",
    "mailoney", "miniprint", "p0f", "redishoneypot", "sentrypeer",
    "suricata", "tanner", "wordpot"
]

packet_counter = {hp: 0 for hp in HONEYPOT_NAMES}
for hp in HONEYPOT_NAMES:
    os.makedirs(os.path.join(LOCAL_BASE, hp), exist_ok=True)

# --------------------------------------------------------------
def print_status():
    print("\n================ ACTIVE HONEYPOT COUNTS ================")
    for hp in HONEYPOT_NAMES:
        print(f"{hp:<15} : {packet_counter[hp]}")
    print("========================================================\n")

# --------------------------------------------------------------
def extract_honeypot_name(path):
    p = path.lower()
    for hp in HONEYPOT_NAMES:
        if f"/{hp}/" in p:
            return hp
    for piece in p.split("/"):
        if piece in HONEYPOT_NAMES:
            return piece
    return None

# --------------------------------------------------------------
def convert_to_csv(local_txt, out_csv, hp_name):
    rows = []
    try:
        with open(local_txt, "r", encoding="utf8", errors="ignore") as f:
            for line in f:
                try:
                    rows.append(json.loads(line.strip()))
                except:
                    continue
    except:
        return 0

    if not rows:
        return 0

    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)

    count = len(df)
    packet_counter[hp_name] += count

    print(f"[LOG] {hp_name:<12}  +{count} rows  (total {packet_counter[hp_name]})")

    return count

# --------------------------------------------------------------
def connect_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("[INFO] Connecting to AWS...")

    ssh.connect(
        hostname=AWS_IP, port=AWS_PORT, username=AWS_USER,
        key_filename=PEM_PATH, look_for_keys=False, allow_agent=False
    )
    return ssh, ssh.open_sftp()

# --------------------------------------------------------------
def is_file(a):
    return not (a.st_mode & 0o40000)

def find_recent_logs(sftp, base, cutoff):
    items = []
    try:
        entries = sftp.listdir_attr(base)
    except:
        return items

    for e in entries:
        p = f"{base}/{e.filename}"
        if not is_file(e):
            items += find_recent_logs(sftp, p, cutoff)
            continue
        if not any(e.filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
            continue
        if e.st_mtime >= cutoff:
            items.append(p)
    return items

# --------------------------------------------------------------
def main():
    ssh, sftp = connect_ssh()

    cutoff_ts = (datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)).timestamp()

    print("\n[INFO] Pulling ALL logs from the past 24 hours for active honeypots.")
    print_status()

    while True:
        logs = find_recent_logs(sftp, REMOTE_BASE, cutoff_ts)

        for remote_file in logs:
            hp = extract_honeypot_name(remote_file)
            if hp is None:
                continue

            rel = remote_file.replace(REMOTE_BASE, "").lstrip("/")
            local_txt = os.path.join(LOCAL_BASE, rel)
            os.makedirs(os.path.dirname(local_txt), exist_ok=True)

            try:
                sftp.get(remote_file, local_txt)
            except:
                continue

            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            out_csv = f"{local_txt}_{ts}.csv"

            convert_to_csv(local_txt, out_csv, hp)

        print_status()
        time.sleep(8)

    sftp.close()
    ssh.close()

# --------------------------------------------------------------
if __name__ == "__main__":
    main()
