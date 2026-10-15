#!/usr/bin/env python3
"""auth.log analyzer — Linux kimlik doğrulama loglarını analiz eder.

Kullanım:
    python analyzer.py /var/log/auth.log
    python analyzer.py auth.log auth.log.1 auth.log.2.gz --threshold 10 --window 5
    python analyzer.py auth.log --json rapor.json
"""
import argparse
import gzip
import json
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

# Satır başlığı: klasik syslog ve ISO8601 (yeni rsyslog) formatı
SYSLOG_HDR = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
ISO_HDR = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

IP = r"(?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
# Sıra önemli: ilk eşleşen kazanır
PATTERNS = [
    ("ssh_failed",   re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S*) from " + IP)),
    ("ssh_accepted", re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP)),
    ("ssh_invalid",  re.compile(r"Invalid user (?P<user>\S*) from " + IP)),
    ("sudo",         re.compile(r"^\s*(?P<user>\S+) : (?:(?P<fail>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")),
    ("sudo_fail",    re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*?user=(?P<user>\S+)")),
    ("su_ok",        re.compile(r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>\S+?) by (?P<user>[^(\s]+)")),
    ("su_fail",      re.compile(r"(?:FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+)|pam_unix\(su(?:-l)?:auth\): authentication failure;.*?ruser=(?P<ruser>\S*))")),
    ("user_add",     re.compile(r"new user: name=(?P<user>[^,]+)")),
    ("user_del",     re.compile(r"delete user '(?P<user>[^']+)'")),
    ("group_add",    re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
    ("passwd_chg",   re.compile(r"password changed for (?P<user>\S+)")),
]

SENSITIVE_GROUPS = {"sudo", "wheel", "admin", "root", "adm", "docker", "lxd"}
SUSPICIOUS_CMD = re.compile(
    r"(/bin/(ba|z|da)?sh\b|\bnc\b|\bncat\b|netcat|wget |curl .*\|\s*(ba)?sh|chmod \+s|"
    r"/etc/shadow|/etc/sudoers|useradd|usermod|passwd|base64 -d|python[0-9.]* -c|perl -e|"
    r"iptables -F|history -c|rm -rf /)"
)
FAIL_KINDS = ("ssh_failed", "ssh_invalid")


@dataclass
class Event:
    ts: datetime
    host: str
    proc: str
    kind: str
    user: str | None = None
    ip: str | None = None
    extra: dict | None = None


def open_any(path):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def parse_lines(lines, year):
    """Klasik syslog'da yıl yok; aralık→ocak geçişinde yılı ilerletir."""
    last = None
    for line in lines:
        line = line.rstrip("\n")
        iso = False
        m = SYSLOG_HDR.match(line)
        if not m:
            m = ISO_HDR.match(line)
            iso = True
        if not m:
            continue
        try:
            if iso:
                ts = datetime.fromisoformat(m["ts"])
            else:
                ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        if not iso and last and ts < last - timedelta(days=180):
            year += 1
            ts = ts.replace(year=year)
        last = ts
        for kind, rx in PATTERNS:
            p = rx.search(m["msg"])
            if not p:
                continue
            g = {k: v for k, v in p.groupdict().items() if v}
            user = g.pop("user", None) or g.pop("ruser", None)
            ip = g.pop("ip", None)
            yield Event(ts, m["host"], m["proc"], kind, user, ip, g or None)
            break


def dedupe_failures(events, gap=timedelta(seconds=5)):
    """OpenSSH geçersiz kullanıcıda hem 'Invalid user' hem 'Failed password' yazar.
    Aynı IP+kaynak portundan kısa aralıkla gelen çiftleri tek deneme sayar."""
    last, out = {}, []
    for e in events:
        if e.kind not in FAIL_KINDS or not e.ip:
            continue
        port = (e.extra or {}).get("port")
        if port:
            key = (e.ip, port)
            if key in last and e.ts - last[key] <= gap:
                last[key] = e.ts
                continue
            last[key] = e.ts
        out.append(e)
    return out


def detect_bruteforce(fails, threshold, window_min):
    """Kayan pencere: aynı IP'den pencere içinde >= threshold başarısız deneme."""
    window = timedelta(minutes=window_min)
    per_ip = defaultdict(list)
    for e in fails:
        per_ip[e.ip].append(e)

    alerts = []
    for ip, evs in per_ip.items():
        q = deque()
        peak, peak_start = 0, None
        for e in evs:  # events zaten zamana göre sıralı
            q.append(e)
            while q[0].ts < e.ts - window:
                q.popleft()
            if len(q) > peak:
                peak, peak_start = len(q), q[0].ts
        if peak >= threshold:
            alerts.append({
                "ip": ip,
                "total_failures": len(evs),
                "peak_in_window": peak,
                "peak_start": peak_start.isoformat(),
                "first_seen": evs[0].ts.isoformat(),
                "last_seen": evs[-1].ts.isoformat(),
                "users_tried": sorted({e.user for e in evs if e.user})[:20],
            })
    return sorted(alerts, key=lambda a: -a["total_failures"])


def analyze(events, threshold, window):
    c = Counter(e.kind for e in events)
    fails = dedupe_failures(events)
    failed_ip = Counter(e.ip for e in fails)
    failed_user = Counter(e.user for e in fails if e.user)
    accepted = [e for e in events if e.kind == "ssh_accepted"]
    bf = detect_bruteforce(fails, threshold, window)
    bf_ips = {a["ip"] for a in bf}

    # En kritik bulgu: başarısız denemelerden sonra aynı IP'den başarılı giriş
    fails_by_ip = defaultdict(list)
    for e in fails:
        fails_by_ip[e.ip].append(e.ts)
    compromised = []
    for e in accepted:
        prior = sum(1 for t in fails_by_ip.get(e.ip, ()) if t <= e.ts)
        if prior:
            compromised.append({
                "ts": e.ts.isoformat(), "ip": e.ip, "user": e.user,
                "method": (e.extra or {}).get("method"),
                "prior_failures": prior, "bruteforce_ip": e.ip in bf_ips,
            })

    sudo = [e for e in events if e.kind == "sudo"]
    hours = Counter(e.ts.hour for e in fails)

    return {
        "failed_attempts": len(fails),
        "period": {
            "start": events[0].ts.isoformat() if events else None,
            "end": events[-1].ts.isoformat() if events else None,
        },
        "counts": dict(c),
        "top_failed_ips": failed_ip.most_common(10),
        "top_failed_users": failed_user.most_common(10),
        "successful_logins": [
            {"ts": e.ts.isoformat(), "user": e.user, "ip": e.ip, "method": (e.extra or {}).get("method")}
            for e in accepted
        ],
        "bruteforce": bf,
        "possible_compromise": compromised,
        "sudo_suspicious": [
            {"ts": e.ts.isoformat(), "user": e.user, "as": e.extra.get("target"), "cmd": e.extra.get("cmd")}
            for e in sudo if e.extra and SUSPICIOUS_CMD.search(e.extra.get("cmd", ""))
        ],
        "sudo_denied": [
            {"ts": e.ts.isoformat(), "user": e.user, "reason": e.extra.get("fail"), "cmd": e.extra.get("cmd")}
            for e in sudo if e.extra and e.extra.get("fail")
        ],
        "account_changes": [
            {"ts": e.ts.isoformat(), "kind": e.kind, "user": e.user, **(e.extra or {}),
             "sensitive": e.kind == "group_add" and (e.extra or {}).get("group") in SENSITIVE_GROUPS}
            for e in events if e.kind in ("user_add", "user_del", "group_add", "passwd_chg")
        ],
        "failed_by_hour": {h: hours.get(h, 0) for h in range(24)},
    }


# ----------------------------- Çıktı -----------------------------
USE_COLOR = sys.stdout.isatty()


def col(s, code):
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


RED, YEL, GRN, BLD, DIM = "31;1", "33", "32", "1", "2"


def section(title):
    print("\n" + col(f"== {title} ", BLD) + col("=" * max(0, 60 - len(title)), DIM))


def print_report(r, top):
    c = r["counts"]
    section("Özet")
    print(f"  Dönem          : {r['period']['start']}  →  {r['period']['end']}")
    print(f"  Başarısız SSH  : {r['failed_attempts']} deneme   (ham satır: {c.get('ssh_failed', 0)} hata + {c.get('ssh_invalid', 0)} geçersiz kullanıcı)")
    print(f"  Başarılı SSH   : {c.get('ssh_accepted', 0)}")
    print(f"  sudo komutları : {c.get('sudo', 0)}   (sudo auth hatası: {c.get('sudo_fail', 0)})")
    print(f"  su             : {c.get('su_ok', 0)} başarılı / {c.get('su_fail', 0)} başarısız")

    if r["possible_compromise"]:
        section("!! OLASI ELE GEÇİRME — başarısız denemelerden sonra başarılı giriş")
        for x in r["possible_compromise"]:
            tag = " [BRUTE-FORCE IP]" if x["bruteforce_ip"] else ""
            print(col(f"  {x['ts']}  {x['user']}@{x['ip']}  ({x['method']}), öncesinde {x['prior_failures']} hata{tag}", RED))

    section(f"Brute-force tespitleri ({len(r['bruteforce'])})")
    if not r["bruteforce"]:
        print(col("  Yok", GRN))
    for a in r["bruteforce"][:top]:
        users = ", ".join(a["users_tried"][:6]) + (" …" if len(a["users_tried"]) > 6 else "")
        print(col(f"  {a['ip']:<40}", YEL) +
              f" toplam {a['total_failures']:>5} | pencerede tepe {a['peak_in_window']:>4} | {a['first_seen']} → {a['last_seen']}")
        print(col(f"      denenen: {users}", DIM))

    section("En çok başarısız deneme yapan IP'ler")
    for ip, n in r["top_failed_ips"][:top]:
        print(f"  {n:>6}  {ip}")

    section("En çok denenen kullanıcı adları")
    for u, n in r["top_failed_users"][:top]:
        print(f"  {n:>6}  {u}")

    section("Başarılı girişler")
    if not r["successful_logins"]:
        print("  Yok")
    for x in r["successful_logins"][-top:]:
        mark = col(" ← root", RED) if x["user"] == "root" else ""
        print(f"  {x['ts']}  {x['user']:<14} {x['ip']:<40} {x['method']}{mark}")

    if r["sudo_suspicious"] or r["sudo_denied"]:
        section("Şüpheli / reddedilen sudo")
        for x in r["sudo_suspicious"]:
            print(col(f"  {x['ts']}  {x['user']} → {x['as']}: {x['cmd']}", YEL))
        for x in r["sudo_denied"]:
            print(col(f"  {x['ts']}  {x['user']} REDDEDİLDİ ({x['reason']}): {x['cmd']}", RED))

    if r["account_changes"]:
        section("Hesap değişiklikleri")
        for x in r["account_changes"]:
            detail = f" → grup {x['group']}" if x.get("group") else ""
            line = f"  {x['ts']}  {x['kind']:<10} {x['user']}{detail}"
            print(col(line, RED) if x["sensitive"] else line)

    section("Saate göre başarısız denemeler")
    mx = max(r["failed_by_hour"].values()) or 1
    for h, n in r["failed_by_hour"].items():
        if n:
            print(f"  {h:02d}:00  {'█' * max(1, round(n / mx * 40))} {n}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Linux auth.log analizörü")
    ap.add_argument("files", nargs="+", help="auth.log dosyaları (.gz desteklenir, '-' = stdin)")
    ap.add_argument("-t", "--threshold", type=int, default=5, help="brute-force eşiği (varsayılan 5)")
    ap.add_argument("-w", "--window", type=int, default=10, help="brute-force penceresi, dakika (varsayılan 10)")
    ap.add_argument("-y", "--year", type=int, default=datetime.now().year,
                    help="klasik syslog formatında başlangıç yılı")
    ap.add_argument("-n", "--top", type=int, default=10, help="listelerde gösterilecek satır sayısı")
    ap.add_argument("--json", metavar="DOSYA", help="raporu JSON olarak yaz ('-' = stdout)")
    ap.add_argument("--blocklist", metavar="DOSYA",
                    help="brute-force IP'lerini satır satır yaz (iptables/ipset/fail2ban için)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    events = []
    for f in args.files:
        try:
            with open_any(f) as fh:
                events.extend(parse_lines(fh, args.year))
        except OSError as e:
            print(f"hata: {f}: {e}", file=sys.stderr)
    events.sort(key=lambda e: e.ts)

    report = analyze(events, args.threshold, args.window)

    if args.blocklist:
        with open(args.blocklist, "w", encoding="utf-8") as fh:
            fh.writelines(a["ip"] + "\n" for a in report["bruteforce"])

    if args.json == "-":
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        return
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
    print_report(report, args.top)
    # Çıkış kodu: 2 = olası ele geçirme, 1 = brute-force, 0 = temiz
    sys.exit(2 if report["possible_compromise"] else 1 if report["bruteforce"] else 0)


if __name__ == "__main__":
    main()
