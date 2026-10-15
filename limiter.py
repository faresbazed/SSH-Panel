#!/usr/bin/env python3
import glob
import os
import subprocess
import time
from datetime import datetime

USERS_DIR = "/etc/ssh-panel/users"


def check_and_enforce():
    if not os.path.exists(USERS_DIR):
        return

    today = datetime.now().strftime("%Y-%m-%d")

    for user_file in glob.glob(os.path.join(USERS_DIR, "*.conf")):
        username = os.path.basename(user_file)[:-5]
        max_limit = 2
        expiry = "2099-12-31"

        try:
            with open(user_file, "r") as f:
                for line in f:
                    if line.startswith("LIMIT="):
                        max_limit = int(line.strip().split("=", 1)[1])
                    elif line.startswith("EXPIRY="):
                        expiry = line.strip().split("=", 1)[1]
        except Exception:
            continue

        # Lock expired SSH users
        if expiry < today:
            subprocess.run(["usermod", "-L", username], stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-u", username], stderr=subprocess.DEVNULL)
            continue

        # Count active SSH processes for user
        try:
            out = subprocess.check_output(
                ["pgrep", "-u", username, "sshd|dropbear"], stderr=subprocess.DEVNULL
            ).decode()
            pids = [p for p in out.strip().split("\n") if p]
            if max_limit > 0 and len(pids) > max_limit:
                for pid in pids[max_limit:]:
                    subprocess.run(["kill", "-9", pid], stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass


if __name__ == "__main__":
    while True:
        try:
            check_and_enforce()
        except Exception:
            pass
        time.sleep(10)
