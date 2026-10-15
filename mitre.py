"""Rapor bulgularını MITRE ATT&CK tekniklerine eşler.

Eşleme yalnızca logda görülen davranışa dayanır; bir tekniğin listelenmesi
saldırının başarılı olduğunu değil, o tekniğe uyan bir iz bulunduğunu gösterir.
"""
import re

# id: (ad, taktik)
TECHNIQUES = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1059.006": ("Command and Scripting Interpreter: Python", "Execution"),
    "T1059":     ("Command and Scripting Interpreter", "Execution"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1098":     ("Account Manipulation", "Persistence"),
    "T1548.001": ("Abuse Elevation Control Mechanism: Setuid and Setgid", "Privilege Escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1140":     ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1105":     ("Ingress Tool Transfer", "Command and Control"),
    "T1095":     ("Non-Application Layer Protocol", "Command and Control"),
    "T1531":     ("Account Access Removal", "Impact"),
    "T1485":     ("Data Destruction", "Impact"),
}

TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Lateral Movement", "Command and Control", "Impact"]

# sudo ile çalıştırılan komut → teknik
SUDO_CMD_TECHNIQUES = [
    (re.compile(r"/etc/g?shadow"), "T1003.008"),
    (re.compile(r"/bin/(ba|z|da)?sh\b"), "T1059.004"),
    (re.compile(r"python[0-9.]* -c"), "T1059.006"),
    (re.compile(r"perl -e"), "T1059"),
    (re.compile(r"/etc/sudoers"), "T1548.003"),
    (re.compile(r"useradd"), "T1136.001"),
    (re.compile(r"usermod|passwd"), "T1098"),
    (re.compile(r"chmod \+s"), "T1548.001"),
    (re.compile(r"history -c"), "T1070.003"),
    (re.compile(r"iptables -F"), "T1562.004"),
    (re.compile(r"base64 -d"), "T1140"),
    (re.compile(r"wget |curl "), "T1105"),
    (re.compile(r"\bnc\b|\bncat\b|netcat"), "T1095"),
    (re.compile(r"rm -rf /"), "T1485"),
]

ACCOUNT_TECHNIQUES = {"user_add": "T1136.001", "passwd_chg": "T1098", "user_del": "T1531"}


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def map_report(r, max_evidence=5):
    """analyze() çıktısından teknik listesi üretir (taktik sırasına göre)."""
    hits = {}

    def add(tid, evidence):
        hits.setdefault(tid, []).append(evidence)

    for a in r["bruteforce"]:
        add("T1110.001", f"{a['ip']}: {a['total_failures']} başarısız deneme")

    for x in r["possible_compromise"]:
        ev = f"{x['ts']} {x['user']}@{x['ip']}, öncesinde {x['prior_failures']} hata"
        add("T1078.003", ev)
        add("T1021.004", ev)

    denied = {(x["ts"], x["user"], x["cmd"]) for x in r["sudo_denied"]}
    for x in r["sudo_denied"]:
        add("T1548.003", f"{x['ts']} {x['user']} reddedildi: {x['cmd']}")
    for x in r["sudo_suspicious"]:
        if (x["ts"], x["user"], x["cmd"]) in denied:
            continue  # çalışmadı, yukarıda deneme olarak sayıldı
        for rx, tid in SUDO_CMD_TECHNIQUES:
            if rx.search(x["cmd"] or ""):
                add(tid, f"{x['ts']} {x['user']} → {x['as']}: {x['cmd']}")

    for x in r["account_changes"]:
        tid = "T1098" if x["kind"] == "group_add" and x["sensitive"] else ACCOUNT_TECHNIQUES.get(x["kind"])
        if tid:
            detail = f" → grup {x['group']}" if x.get("group") else ""
            add(tid, f"{x['ts']} {x['kind']} {x['user']}{detail}")

    out = []
    for tid, evs in hits.items():
        name, tactic = TECHNIQUES[tid]
        out.append({"id": tid, "name": name, "tactic": tactic, "url": technique_url(tid),
                    "count": len(evs), "evidence": evs[:max_evidence]})
    return sorted(out, key=lambda t: (TACTIC_ORDER.index(t["tactic"]), t["id"]))
