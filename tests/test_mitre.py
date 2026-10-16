"""MITRE ATT&CK eşlemesi için testler."""
import unittest

from mitre import TACTIC_ORDER, TECHNIQUES, technique_url
from tests.test_analyzer import run


def ids(r):
    return [t["id"] for t in r["mitre"]]


class MitreMappingTests(unittest.TestCase):
    def test_bruteforce_maps_to_password_guessing(self):
        lines = "\n".join(
            f"Oct 15 09:12:{s:02d} web01 sshd[{1300 + s}]: Failed password for root from 203.0.113.45 port {40100 + s} ssh2"
            for s in range(0, 10, 2))
        self.assertEqual(ids(run(lines)), ["T1110.001"])

    def test_compromise_maps_to_valid_accounts_and_ssh(self):
        r = run("""
Oct 15 13:44:02 web01 sshd[1501]: Failed password for deploy from 203.0.113.77 port 60210 ssh2
Oct 15 13:44:05 web01 sshd[1503]: Failed password for deploy from 203.0.113.77 port 60212 ssh2
Oct 15 13:44:08 web01 sshd[1505]: Failed password for deploy from 203.0.113.77 port 60214 ssh2
Oct 15 13:44:14 web01 sshd[1509]: Accepted password for deploy from 203.0.113.77 port 60218 ssh2
""")
        self.assertEqual(ids(r), ["T1078.003", "T1021.004"])

    def test_shadow_read_via_sudo_maps_to_credential_dumping(self):
        r = run("""
Oct 14 03:23:40 web01 sudo:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
""")
        self.assertEqual(ids(r), ["T1003.008"])

    def test_denied_sudo_is_attempt_not_execution(self):
        # Reddedilen "sudo /bin/bash" çalışmadı: Unix Shell (T1059.004) sayılmamalı
        r = run("""
Oct 15 13:46:30 web01 sudo:   deploy : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
""")
        self.assertEqual(ids(r), ["T1548.003"])

    def test_new_user_added_to_sudo_group(self):
        r = run("""
Oct 14 03:24:02 web01 useradd[2311]: new user: name=backup2, UID=1002, GID=1002, home=/home/backup2, shell=/bin/bash
Oct 14 03:24:05 web01 usermod[2315]: add 'backup2' to group 'sudo'
""")
        self.assertEqual(ids(r), ["T1098", "T1136.001"])

    def test_clean_log_has_no_techniques(self):
        r = run("""
Oct 15 08:01:12 web01 sshd[1201]: Accepted publickey for yusuf from 192.0.2.10 port 51122 ssh2
Oct 15 08:05:40 web01 sudo:    yusuf : TTY=pts/0 ; PWD=/home/yusuf ; USER=root ; COMMAND=/usr/bin/apt update
""")
        self.assertEqual(r["mitre"], [])

    def test_technique_table_is_consistent(self):
        for tid, (name, tactic) in TECHNIQUES.items():
            self.assertIn(tactic, TACTIC_ORDER, tid)
        self.assertEqual(technique_url("T1110.001"), "https://attack.mitre.org/techniques/T1110/001/")


if __name__ == "__main__":
    unittest.main()
