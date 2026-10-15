"""Test için sahte auth.log üretir (samples/auth.log)."""
import random
import sys

random.seed(7)
L = []


def add(t, proc, msg):
    L.append(f"{t} web01 {proc}: {msg}")


users = ["admin", "test", "oracle", "postgres", "ubuntu", "git", "root", "user", "pi", "ftp"]
# 203.0.113.45: brute-force, sonra başarılı giriş + kötü niyetli işlemler
for i in range(40):
    t = f"Oct 14 03:{10 + i // 4:02d}:{(i * 7) % 60:02d}"
    u = random.choice(users)
    if u in ("root", "ubuntu"):
        add(t, "sshd[2201]", f"Failed password for {u} from 203.0.113.45 port {40000 + i} ssh2")
    else:
        add(t, "sshd[2201]", f"Invalid user {u} from 203.0.113.45 port {40000 + i}")
        add(t, "sshd[2201]", f"Failed password for invalid user {u} from 203.0.113.45 port {40000 + i} ssh2")
add("Oct 14 03:21:12", "sshd[2290]", "Accepted password for ubuntu from 203.0.113.45 port 41999 ssh2")
add("Oct 14 03:23:40", "sudo", "   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
add("Oct 14 03:24:02", "useradd[2311]", "new user: name=backup2, UID=1002, GID=1002, home=/home/backup2, shell=/bin/bash")
add("Oct 14 03:24:05", "usermod[2315]", "add 'backup2' to group 'sudo'")
# 198.51.100.7: yavaş tarama (pencereye takılmamalı)
for i in range(12):
    add(f"Oct 14 {5 + i:02d}:00:13", "sshd[3100]", f"Failed password for root from 198.51.100.7 port {5000 + i} ssh2")
# Meşru trafik
add("Oct 14 09:02:11", "sshd[4001]", "Accepted publickey for yusuf from 192.168.1.20 port 53122 ssh2: ED25519 SHA256:abc")
add("Oct 14 09:05:30", "sudo", "    yusuf : TTY=pts/0 ; PWD=/home/yusuf ; USER=root ; COMMAND=/usr/bin/apt update")
add("Oct 14 09:40:00", "sudo", "    intern : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/intern ; USER=root ; COMMAND=/bin/bash")
add("Oct 14 10:12:44", "su[4500]", "pam_unix(su:session): session opened for user root by yusuf(uid=1000)")
add("Oct 14 11:00:01", "su[4600]", "pam_unix(su:auth): authentication failure; logname=intern uid=1003 euid=0 tty=pts/2 ruser=intern rhost=  user=root")

L.sort()
out = sys.argv[1] if len(sys.argv) > 1 else "samples/auth.log"
with open(out, "w") as f:
    f.write("\n".join(L) + "\n")
print(f"{len(L)} satir yazildi -> {out}")
