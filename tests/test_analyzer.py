"""Analizörün sayma ve tespit kuralları için testler.

Çalıştırmak için proje klasöründe: python -m unittest -v
"""
import unittest

from analyzer import analyze, parse_lines


def run(log, threshold=5, window=10, min_prior=3):
    events = sorted(parse_lines(log.strip().splitlines(), 2026), key=lambda e: e.ts)
    return analyze(events, threshold, window, min_prior)


class FailureCountTests(unittest.TestCase):
    def test_invalid_user_attempt_counted_once(self):
        # OpenSSH aynı deneme için iki satır yazar
        r = run("""
Oct 15 10:30:20 web01 sshd[1401]: Invalid user admin from 198.51.100.23 port 55001
Oct 15 10:30:20 web01 sshd[1401]: Failed password for invalid user admin from 198.51.100.23 port 55001 ssh2
""")
        self.assertEqual(r["failed_attempts"], 1)
        self.assertEqual(r["top_failed_users"], [("admin", 1)])

    def test_multiple_passwords_on_one_connection_counted_separately(self):
        # Hydra gibi araçlar aynı bağlantıda birden fazla parola dener
        r = run("""
Oct 15 09:00:01 web01 sshd[100]: Failed password for root from 203.0.113.9 port 40000 ssh2
Oct 15 09:00:03 web01 sshd[100]: Failed password for root from 203.0.113.9 port 40000 ssh2
Oct 15 09:00:05 web01 sshd[100]: Failed password for root from 203.0.113.9 port 40000 ssh2
""")
        self.assertEqual(r["failed_attempts"], 3)

    def test_invalid_user_without_password_still_counted(self):
        # Parola denenmeden kopan bağlantı da bir denemedir
        r = run("""
Oct 15 09:10:00 web01 sshd[200]: Invalid user bob from 203.0.113.9 port 41000
""")
        self.assertEqual(r["failed_attempts"], 1)


class DetectionTests(unittest.TestCase):
    def test_success_after_failures_is_possible_compromise(self):
        r = run("""
Oct 15 13:44:02 web01 sshd[1501]: Failed password for deploy from 203.0.113.77 port 60210 ssh2
Oct 15 13:44:05 web01 sshd[1503]: Failed password for deploy from 203.0.113.77 port 60212 ssh2
Oct 15 13:44:08 web01 sshd[1505]: Failed password for deploy from 203.0.113.77 port 60214 ssh2
Oct 15 13:44:14 web01 sshd[1509]: Accepted password for deploy from 203.0.113.77 port 60218 ssh2
""")
        self.assertEqual(len(r["possible_compromise"]), 1)
        hit = r["possible_compromise"][0]
        self.assertEqual((hit["user"], hit["ip"], hit["prior_failures"]), ("deploy", "203.0.113.77", 3))

    def test_single_failure_before_success_is_not_flagged(self):
        # Parmak kayması: tek yanlış parola sonrası başarılı giriş alarm üretmemeli
        r = run("""
Oct 15 15:15:41 web01 sshd[1068]: Failed password for yusuf from 10.0.2.1 port 58123 ssh2
Oct 15 15:15:45 web01 sshd[1068]: Accepted password for yusuf from 10.0.2.1 port 58123 ssh2
""")
        self.assertEqual(r["possible_compromise"], [])

    def test_old_failures_outside_window_are_not_counted(self):
        # Girişten saatler önceki hatalar ele geçirme sayılmaz
        r = run("""
Oct 15 09:00:00 web01 sshd[100]: Failed password for deploy from 203.0.113.77 port 60210 ssh2
Oct 15 09:00:03 web01 sshd[102]: Failed password for deploy from 203.0.113.77 port 60212 ssh2
Oct 15 09:00:06 web01 sshd[104]: Failed password for deploy from 203.0.113.77 port 60214 ssh2
Oct 15 13:44:14 web01 sshd[1509]: Accepted password for deploy from 203.0.113.77 port 60218 ssh2
""")
        self.assertEqual(r["possible_compromise"], [])

    def test_clean_login_is_not_flagged(self):
        r = run("""
Oct 15 08:01:12 web01 sshd[1201]: Accepted publickey for yusuf from 192.0.2.10 port 51122 ssh2
""")
        self.assertEqual(r["possible_compromise"], [])
        self.assertEqual(r["bruteforce"], [])

    def test_denied_sudo_not_listed_as_suspicious(self):
        r = run("""
Oct 15 13:46:30 web01 sudo:   deploy : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
""")
        self.assertEqual(r["sudo_suspicious"], [])
        self.assertEqual(len(r["sudo_denied"]), 1)

    def test_bruteforce_threshold_inside_window(self):
        lines = "\n".join(
            f"Oct 15 09:12:{s:02d} web01 sshd[{1300 + s}]: Failed password for root from 203.0.113.45 port {40100 + s} ssh2"
            for s in range(0, 10, 2))  # 10 saniyede 5 deneme
        r = run(lines, threshold=5, window=10)
        self.assertEqual([a["ip"] for a in r["bruteforce"]], ["203.0.113.45"])

    def test_slow_attempts_below_threshold_not_bruteforce(self):
        # Saatte bir deneme, 10 dakikalık pencerede eşiğe ulaşmaz
        lines = "\n".join(
            f"Oct 15 {h:02d}:00:13 web01 sshd[3100]: Failed password for root from 198.51.100.7 port {5000 + h} ssh2"
            for h in range(5, 17))
        r = run(lines, threshold=5, window=10)
        self.assertEqual(r["failed_attempts"], 12)
        self.assertEqual(r["bruteforce"], [])


if __name__ == "__main__":
    unittest.main()
