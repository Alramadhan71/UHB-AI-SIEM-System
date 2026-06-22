"""
=============================================================
 SIEM Web Dashboard — Windows Agent Receiver
 Run with:  python siem_web.py
 Dashboard: http://localhost:5000   login: admin / admin123

 Receives logs ONLY from the Windows SIEM Agent via:
   UDP port 517  (SIEMAgent.exe — UDP mode)
   TCP port 517  (SIEMAgent.exe — TCP mode)

 Schema follows the Recommended Storage Schema from the
 Windows SIEM Agent Professional Technical Documentation.
=============================================================
"""

import os, socket, sqlite3, json, threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from functools import wraps

import requests

from flask import (Flask, render_template, jsonify, request,
                   session, redirect, url_for, Response, stream_with_context)
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================
# PATHS & CONFIG
# =============================================================
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DB_FILE         = os.environ.get("SIEM_DB_FILE", os.path.join(BASE_DIR, 'siem.db'))
WIN_AGENT_PORT  = 517
WIN_AGENT_PORTS = (517, 518)
HTTP_PORT       = int(os.environ.get("HTTP_PORT", "5000"))
UDP_BUFFER_SIZE = 65535
TCP_BUFFER_SIZE = 65535
RULES_CACHE_TTL = 30
ALERT_COOLDOWN  = 60
SECRET_KEY      = os.environ.get("SECRET_KEY", 'siem-secret-key-2024-change-in-production')

# ---- Local AI (Ollama) ----
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_CHAT_URL = f"{OLLAMA_BASE_URL}/api/chat"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"
OLLAMA_REQUEST_TIMEOUT = int(os.environ.get("OLLAMA_REQUEST_TIMEOUT", "60"))
OLLAMA_STATUS_TIMEOUT  = int(os.environ.get("OLLAMA_STATUS_TIMEOUT", "5"))
LMSTUDIO_BASE_URL = OLLAMA_BASE_URL
LMSTUDIO_CHAT_URL = OLLAMA_CHAT_URL
LMSTUDIO_MODEL = OLLAMA_MODEL
AI_MAX_QUESTION_LEN = 1600
AI_NUM_PREDICT = int(os.environ.get("AI_NUM_PREDICT", "260"))
AI_NUM_CTX = int(os.environ.get("AI_NUM_CTX", "2048"))
AI_MODEL_PROFILES = {
    "fast": {
        "id": "fast",
        "label": "Fast",
        "model": "llama3.2:3b",
        "quality": "Good",
        "speed": "High",
        "recommended": True,
        "description": "Recommended for live demos and quick triage.",
    },
    "deep": {
        "id": "deep",
        "label": "Deep",
        "model": "qwen3:8b",
        "quality": "Higher",
        "speed": "Slower",
        "recommended": False,
        "description": "Richer analysis, but may take longer on this machine.",
    },
}

# =============================================================
# GLOBAL STATE
# =============================================================
rules_cache       = []
rules_lock        = threading.Lock()
rules_last_loaded = datetime.min
alert_cooldowns   = {}
cooldown_lock     = threading.Lock()
stats             = {"received": 0, "alerts": 0, "errors": 0}
stats_lock        = threading.Lock()

# =============================================================
# FLASK APP
# =============================================================
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static'),
)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# =============================================================
# DATABASE  — Recommended Storage Schema
# =============================================================
def get_conn():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    conn = get_conn()

    # ---- Main log table (Recommended Storage Schema) ----
    conn.execute("""
        CREATE TABLE IF NOT EXISTS windows_logs (
            id                  INTEGER  PRIMARY KEY AUTOINCREMENT,
            agent_id            TEXT     NOT NULL,
            hostname            TEXT,
            ip_agent            TEXT,
            source_type         TEXT,
            event_id            INTEGER,
            level               INTEGER,
            event_timestamp     DATETIME,
            server_receive_time DATETIME NOT NULL DEFAULT (datetime('now')),
            raw_log             TEXT,
            rule_tags           TEXT
        )
    """)

    # ---- Agent tracking ----
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id         INTEGER  PRIMARY KEY AUTOINCREMENT,
            agent_id   TEXT     NOT NULL,
            hostname   TEXT     NOT NULL,
            ip_agent   TEXT,
            os_type    TEXT     DEFAULT 'windows',
            is_active  INTEGER  NOT NULL DEFAULT 1,
            first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
            last_seen  DATETIME NOT NULL DEFAULT (datetime('now')),
            UNIQUE(agent_id, hostname)
        )
    """)

    # ---- Alerts ----
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER  PRIMARY KEY AUTOINCREMENT,
            log_id       INTEGER  NOT NULL REFERENCES windows_logs(id),
            rule_name    TEXT     NOT NULL,
            severity     TEXT     NOT NULL DEFAULT 'medium'
                         CHECK (severity IN ('critical','high','medium','low','info')),
            triggered_at DATETIME NOT NULL DEFAULT (datetime('now')),
            disposition  TEXT     NOT NULL DEFAULT 'open'
                         CHECK (disposition IN
                           ('open','investigating','true_positive','false_positive','closed'))
        )
    """)

    # ---- Detection rules ----
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id              INTEGER  PRIMARY KEY AUTOINCREMENT,
            name            TEXT     NOT NULL UNIQUE,
            condition_type  TEXT     NOT NULL,
            condition_value TEXT,
            severity        TEXT     NOT NULL DEFAULT 'medium',
            is_active       INTEGER  NOT NULL DEFAULT 1,
            created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ---- Users ----
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            username      TEXT     NOT NULL UNIQUE,
            email         TEXT     UNIQUE,
            password_hash TEXT     NOT NULL,
            role          TEXT     NOT NULL DEFAULT 'analyst'
                          CHECK (role IN ('admin', 'analyst', 'viewer')),
            is_active     INTEGER  NOT NULL DEFAULT 1,
            created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
            last_login    DATETIME
        )
    """)

    # ---- Login audit ----
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id           INTEGER  PRIMARY KEY AUTOINCREMENT,
            username     TEXT     NOT NULL,
            ip_address   TEXT,
            success      INTEGER  NOT NULL DEFAULT 0,
            attempted_at DATETIME NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ---- SOC playbooks / runbooks ----
    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbooks (
            id              INTEGER  PRIMARY KEY AUTOINCREMENT,
            slug            TEXT     NOT NULL UNIQUE,
            name            TEXT     NOT NULL,
            summary         TEXT     NOT NULL,
            category        TEXT     NOT NULL,
            severity        TEXT     NOT NULL DEFAULT 'medium'
                            CHECK (severity IN ('critical','high','medium','low','info')),
            mitre_tactics   TEXT,
            mitre_techniques TEXT,
            event_ids       TEXT,
            rule_names      TEXT,
            evidence_items  TEXT,
            escalation      TEXT,
            containment     TEXT,
            is_active       INTEGER  NOT NULL DEFAULT 1,
            created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
            updated_at      DATETIME NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbook_steps (
            id           INTEGER  PRIMARY KEY AUTOINCREMENT,
            playbook_id  INTEGER  NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
            step_order   INTEGER  NOT NULL,
            phase        TEXT     NOT NULL,
            title        TEXT     NOT NULL,
            detail       TEXT     NOT NULL,
            command      TEXT,
            step_type    TEXT     NOT NULL DEFAULT 'manual'
                         CHECK (step_type IN ('manual','evidence','command','containment','escalation')),
            UNIQUE(playbook_id, step_order)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbook_runs (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            playbook_id   INTEGER  NOT NULL REFERENCES playbooks(id),
            alert_id      INTEGER  REFERENCES alerts(id),
            started_by    INTEGER  REFERENCES users(id),
            status        TEXT     NOT NULL DEFAULT 'in_progress'
                          CHECK (status IN ('open','in_progress','completed','cancelled')),
            notes         TEXT,
            started_at    DATETIME NOT NULL DEFAULT (datetime('now')),
            completed_at  DATETIME
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbook_run_steps (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            run_id        INTEGER  NOT NULL REFERENCES playbook_runs(id) ON DELETE CASCADE,
            step_id       INTEGER  NOT NULL REFERENCES playbook_steps(id),
            is_done       INTEGER  NOT NULL DEFAULT 0,
            analyst_notes TEXT,
            completed_at  DATETIME,
            UNIQUE(run_id, step_id)
        )
    """)

    # ---- Seed detection rules ----
    seed_rules = [
        # ── Logon / Authentication ──────────────────────────────────────────
        ('Failed Logon (4625)',                  'event_id',         '4625',                         'high'),
        ('Successful Logon (4624)',              'event_id',         '4624',                         'info'),
        ('Privileged Logon (4672)',              'event_id',         '4672',                         'medium'),
        ('Explicit Credential Use (4648)',       'event_id',         '4648',                         'medium'),
        ('Account Locked Out (4740)',            'event_id',         '4740',                         'high'),
        ('Account Unlocked (4767)',              'event_id',         '4767',                         'medium'),
        ('Kerberos Pre-Auth Failed (4771)',      'event_id',         '4771',                         'high'),
        ('NTLM Authentication Attempt (4776)',   'event_id',         '4776',                         'medium'),
        ('Replay Attack Detected (4649)',        'event_id',         '4649',                         'critical'),
        # ── Account Management ──────────────────────────────────────────────
        ('User Account Created (4720)',          'event_id',         '4720',                         'high'),
        ('User Account Deleted (4726)',          'event_id',         '4726',                         'high'),
        ('User Account Enabled (4722)',          'event_id',         '4722',                         'medium'),
        ('User Account Disabled (4725)',         'event_id',         '4725',                         'medium'),
        ('Password Reset Attempt (4724)',        'event_id',         '4724',                         'high'),
        ('Password Change Attempt (4723)',       'event_id',         '4723',                         'medium'),
        ('Account Name Changed (4781)',          'event_id',         '4781',                         'high'),
        ('Member Added to Global Group (4728)',  'event_id',         '4728',                         'high'),
        ('Member Added to Local Group (4732)',   'event_id',         '4732',                         'high'),
        ('Member Added to Universal Group (4756)','event_id',        '4756',                         'high'),
        ('Member Removed from Group (4729)',     'event_id',         '4729',                         'medium'),
        # ── Privilege Use ───────────────────────────────────────────────────
        ('Sensitive Privilege Use (4673)',       'event_id',         '4673',                         'medium'),
        ('Privileged Object Access (4674)',      'event_id',         '4674',                         'medium'),
        # ── Process & Execution ─────────────────────────────────────────────
        ('New Process Created (4688)',           'event_id',         '4688',                         'info'),
        ('PowerShell Script Block (4104)',       'event_id',         '4104',                         'medium'),
        ('New Service Installed (7045)',         'event_id',         '7045',                         'high'),
        # ── Scheduled Tasks ─────────────────────────────────────────────────
        ('Scheduled Task Created (4698)',        'event_id',         '4698',                         'medium'),
        ('Scheduled Task Deleted (4699)',        'event_id',         '4699',                         'high'),
        ('Scheduled Task Modified (4702)',       'event_id',         '4702',                         'medium'),
        # ── Policy & Audit ──────────────────────────────────────────────────
        ('System Audit Policy Changed (4719)',   'event_id',         '4719',                         'high'),
        ('Domain Policy Changed (4739)',         'event_id',         '4739',                         'high'),
        ('Security Log Cleared (1102)',          'event_id',         '1102',                         'critical'),
        ('Audit Events Dropped (1101)',          'event_id',         '1101',                         'critical'),
        ('Event Log Service Shutdown (1100)',    'event_id',         '1100',                         'high'),
        # ── Network ─────────────────────────────────────────────────────────
        ('Network Share Accessed (5140)',        'event_id',         '5140',                         'medium'),
        ('Network Share Added (5142)',           'event_id',         '5142',                         'high'),
        ('WFP Connection Blocked (5157)',        'event_id',         '5157',                         'medium'),
        # ── System ──────────────────────────────────────────────────────────
        ('Unexpected System Shutdown (6008)',    'event_id',         '6008',                         'high'),
        ('EventLog Service Stopped (6006)',      'event_id',         '6006',                         'high'),
        # ── Windows Defender ────────────────────────────────────────────────
        ('Malware Detected (1116)',              'event_id',         '1116',                         'critical'),
        ('Defender Action Taken (1117)',         'event_id',         '1117',                         'high'),
        ('Defender Action Failed (1118)',        'event_id',         '1118',                         'critical'),
        ('Defender Remediated (1119)',           'event_id',         '1119',                         'medium'),
        ('Defender Real-time Disabled (2004)',   'event_id',         '2004',                         'critical'),
        ('Defender Definition Update Failed (2001)','event_id',      '2001',                         'medium'),
        # ── PowerShell Attack Patterns ───────────────────────────────────────
        ('PowerShell Encoded Command',          'raw_log_contains', '-EncodedCommand',               'critical'),
        ('PowerShell Execution Bypass',         'raw_log_contains', '-ExecutionPolicy Bypass',       'high'),
        ('PowerShell Hidden Window',            'raw_log_contains', '-WindowStyle Hidden',           'high'),
        ('PowerShell IEX Execution',            'raw_log_contains', 'Invoke-Expression',             'high'),
        ('PowerShell Download Cradle',          'raw_log_contains', 'DownloadString',                'critical'),
        # ── Credential Theft Tools ───────────────────────────────────────────
        ('Mimikatz Keyword',                    'raw_log_contains', 'mimikatz',                      'critical'),
        ('LSA Secrets Dump (sekurlsa)',         'raw_log_contains', 'sekurlsa',                      'critical'),
        ('Domain Hash Dump (lsadump)',          'raw_log_contains', 'lsadump',                       'critical'),
        # ── Living-Off-the-Land Binaries ─────────────────────────────────────
        ('CertUtil Decode (LOLBin)',             'raw_log_contains', 'certutil -decode',              'high'),
        ('BITSAdmin Transfer (LOLBin)',          'raw_log_contains', 'bitsadmin /transfer',           'high'),
        ('WMIC Remote Process Create',          'raw_log_contains', 'wmic process call create',      'high'),
        ('Mshta Execution',                     'raw_log_contains', 'mshta',                         'high'),
        # ── Local Privilege Escalation Commands ──────────────────────────────
        ('Net User Add Command',                'raw_log_contains', 'net user /add',                 'high'),
        ('Net Admin Group Add',                 'raw_log_contains', 'net localgroup administrators', 'high'),
    ]
    for name, ctype, cval, sev in seed_rules:
        conn.execute(
            "INSERT OR IGNORE INTO rules (name,condition_type,condition_value,severity) VALUES (?,?,?,?)",
            (name, ctype, cval, sev)
        )

    # ---- Seed default users ----
    conn.execute(
        "INSERT OR IGNORE INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
        ('admin', 'admin@siem.local', generate_password_hash('admin123'), 'admin')
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
        ('analyst', 'analyst@siem.local', generate_password_hash('analyst123'), 'analyst')
    )

    seed_playbooks(conn)

    conn.commit()
    conn.close()
    print("  Database ready.")


def _json_list(values):
    return json.dumps(values or [])


def seed_playbooks(conn):
    playbooks = [
        {
            'slug': 'failed-logon-bruteforce',
            'name': 'Failed Logon / Brute Force Investigation',
            'summary': 'Triage repeated failed Windows logons, identify target accounts, source hosts, and decide whether containment is required.',
            'category': 'Authentication',
            'severity': 'high',
            'event_ids': [4625, 4740, 4771, 4776],
            'rule_names': ['Failed Logon (4625)', 'Account Locked Out (4740)', 'Kerberos Pre-Auth Failed (4771)', 'NTLM Authentication Attempt (4776)'],
            'mitre_tactics': ['Credential Access', 'Initial Access'],
            'mitre_techniques': ['T1110 Brute Force'],
            'evidence_items': ['Target username', 'Source IP or workstation', 'Failure reason/status code', 'Count and time window', 'Any successful login after failures'],
            'escalation': 'Escalate if failures target privileged accounts, originate from unusual hosts, or are followed by successful logon.',
            'containment': 'Disable exposed account, force password reset, block source IP, and isolate host if endpoint compromise is suspected.',
            'steps': [
                ('Triage', 'Confirm the alert scope', 'Check whether the failed logons are isolated or repeated across the same username, host, or IP.', None, 'evidence'),
                ('Investigation', 'Correlate successful logons', 'Look for Event ID 4624 for the same account after the failure burst.', None, 'evidence'),
                ('Investigation', 'Inspect account lockout context', 'If Event ID 4740 exists, identify the caller computer and affected account.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4740} -MaxEvents 20 | Format-List TimeCreated,Message', 'command'),
                ('Containment', 'Protect the account', 'If suspicious, reset the password and disable risky sessions before further analysis.', None, 'containment'),
                ('Escalation', 'Document and escalate', 'Escalate when privileged users, domain controllers, or external-facing services are involved.', None, 'escalation'),
            ],
        },
        {
            'slug': 'privileged-logon',
            'name': 'Privileged Logon Investigation',
            'summary': 'Validate privileged logon activity and determine whether admin access is expected, suspicious, or part of lateral movement.',
            'category': 'Privilege',
            'severity': 'medium',
            'event_ids': [4672, 4624, 4648],
            'rule_names': ['Privileged Logon (4672)', 'Explicit Credential Use (4648)', 'Successful Logon (4624)'],
            'mitre_tactics': ['Privilege Escalation', 'Lateral Movement'],
            'mitre_techniques': ['T1078 Valid Accounts'],
            'evidence_items': ['Admin account', 'Logon type', 'Source host', 'Destination host', 'Time compared to change window'],
            'escalation': 'Escalate if the logon uses a dormant/admin account, occurs outside maintenance windows, or touches multiple hosts.',
            'containment': 'Disable or rotate privileged credentials and isolate the source workstation when credential theft is likely.',
            'steps': [
                ('Triage', 'Validate business context', 'Confirm whether the admin activity matches an approved maintenance or support action.', None, 'manual'),
                ('Investigation', 'Review logon type and source', 'Check whether the logon is interactive, remote interactive, network, or explicit credential use.', None, 'evidence'),
                ('Investigation', 'Check recent admin activity', 'Review nearby 4672/4648 events for the same account across hosts.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4672,4648} -MaxEvents 30 | Format-List TimeCreated,ProviderName,Message', 'command'),
                ('Containment', 'Limit credential exposure', 'If suspicious, revoke sessions and rotate privileged credentials.', None, 'containment'),
            ],
        },
        {
            'slug': 'account-change',
            'name': 'Account or Group Change Investigation',
            'summary': 'Investigate new accounts, deleted accounts, password resets, and group membership changes that can indicate privilege escalation.',
            'category': 'Identity',
            'severity': 'high',
            'event_ids': [4720, 4726, 4724, 4728, 4732, 4756, 4729],
            'rule_names': ['User Account Created (4720)', 'User Account Deleted (4726)', 'Password Reset Attempt (4724)', 'Member Added to Global Group (4728)', 'Member Added to Local Group (4732)', 'Group Membership Changed (4732)', 'Member Added to Universal Group (4756)', 'Member Removed from Group (4729)'],
            'mitre_tactics': ['Persistence', 'Privilege Escalation'],
            'mitre_techniques': ['T1136 Create Account', 'T1098 Account Manipulation'],
            'evidence_items': ['Changed account', 'Actor account', 'Group name', 'Domain controller', 'Ticket or change request'],
            'escalation': 'Escalate immediately if admin groups are modified without an approved request.',
            'containment': 'Remove unauthorized memberships, disable rogue accounts, and rotate credentials for impacted users.',
            'steps': [
                ('Triage', 'Identify actor and target', 'Extract who made the change and which account or group was modified.', None, 'evidence'),
                ('Investigation', 'Validate approval', 'Compare the activity with change tickets, onboarding/offboarding records, or admin maintenance windows.', None, 'manual'),
                ('Investigation', 'Review related account changes', 'Search for adjacent 4720/4728/4732/4756 events on the same host or DC.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4720,4728,4732,4756} -MaxEvents 50 | Format-List TimeCreated,Message', 'command'),
                ('Containment', 'Reverse unauthorized change', 'Remove unapproved group membership or disable the newly created account.', None, 'containment'),
                ('Escalation', 'Escalate privileged changes', 'Escalate any change involving Domain Admins, Enterprise Admins, local Administrators, or service accounts.', None, 'escalation'),
            ],
        },
        {
            'slug': 'powershell-suspicious',
            'name': 'Suspicious PowerShell Response',
            'summary': 'Respond to encoded commands, execution policy bypass, hidden windows, Invoke-Expression, and download cradle behavior.',
            'category': 'PowerShell',
            'severity': 'critical',
            'event_ids': [4104, 4688],
            'rule_names': ['PowerShell Encoded Command', 'PowerShell Execution Bypass', 'PowerShell Hidden Window', 'PowerShell IEX Execution', 'PowerShell Download Cradle', 'PowerShell Script Block (4104)'],
            'mitre_tactics': ['Execution', 'Defense Evasion'],
            'mitre_techniques': ['T1059.001 PowerShell', 'T1027 Obfuscated Files or Information'],
            'evidence_items': ['Full command line', 'Decoded payload', 'Parent process', 'User context', 'Network destination'],
            'escalation': 'Escalate if payload downloads code, runs encoded content, disables controls, or uses admin context.',
            'containment': 'Isolate the host if execution is confirmed malicious, preserve script block logs, and block contacted domains/IPs.',
            'steps': [
                ('Triage', 'Capture command evidence', 'Preserve the full command line and raw event before cleanup actions.', None, 'evidence'),
                ('Investigation', 'Decode encoded content', 'Decode Base64 EncodedCommand safely in an analysis environment and identify intent.', None, 'manual'),
                ('Investigation', 'Review PowerShell logs', 'Collect recent PowerShell operational and script block logs.', 'Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 50 | Format-List TimeCreated,Id,Message', 'command'),
                ('Containment', 'Contain active execution', 'If suspicious code executed, isolate the endpoint and terminate malicious process trees.', None, 'containment'),
                ('Recovery', 'Harden PowerShell logging', 'Enable script block logging, module logging, and constrained language where appropriate.', None, 'manual'),
            ],
        },
        {
            'slug': 'persistence-service-task',
            'name': 'Service or Scheduled Task Persistence',
            'summary': 'Investigate new services and scheduled tasks that may provide persistence or remote execution.',
            'category': 'Persistence',
            'severity': 'high',
            'event_ids': [7045, 4698, 4702, 4699],
            'rule_names': ['New Service Installed (7045)', 'Scheduled Task Created (4698)', 'Scheduled Task Modified (4702)', 'Scheduled Task Deleted (4699)'],
            'mitre_tactics': ['Persistence', 'Privilege Escalation'],
            'mitre_techniques': ['T1543.003 Windows Service', 'T1053.005 Scheduled Task'],
            'evidence_items': ['Service or task name', 'Binary path', 'Run account', 'Creator account', 'File hash and signature'],
            'escalation': 'Escalate if the binary path is user-writable, unsigned, remote, or recently dropped.',
            'containment': 'Disable the service/task, isolate host if binary is malicious, and preserve the executable for analysis.',
            'steps': [
                ('Triage', 'Inspect persistence object', 'Record the service/task name, path, arguments, and run account.', None, 'evidence'),
                ('Investigation', 'Check service configuration', 'Review service path, startup type, and executable signature.', 'Get-CimInstance Win32_Service | Select Name,StartName,State,PathName | Sort Name', 'command'),
                ('Investigation', 'Check scheduled tasks', 'List scheduled tasks and identify suspicious actions or run-as accounts.', 'Get-ScheduledTask | Select TaskName,TaskPath,State | Sort TaskPath,TaskName', 'command'),
                ('Containment', 'Disable persistence', 'Disable the service or task only after preserving evidence.', None, 'containment'),
                ('Recovery', 'Remove artifact and monitor', 'Remove malicious artifacts and monitor for recreation of the same service or task.', None, 'manual'),
            ],
        },
        {
            'slug': 'log-evasion',
            'name': 'Security Log Cleared or EventLog Stopped',
            'summary': 'Respond to log clearing, dropped audit events, or EventLog service shutdown that can indicate defense evasion.',
            'category': 'Defense Evasion',
            'severity': 'critical',
            'event_ids': [1102, 1101, 1100, 6006],
            'rule_names': ['Security Log Cleared (1102)', 'Audit Events Dropped (1101)', 'Event Log Service Shutdown (1100)', 'EventLog Service Stopped (6006)'],
            'mitre_tactics': ['Defense Evasion'],
            'mitre_techniques': ['T1070.001 Clear Windows Event Logs'],
            'evidence_items': ['Actor account', 'Host', 'Time gap', 'Preceding privileged logons', 'Other telemetry source'],
            'escalation': 'Escalate as high confidence compromise if clearing is not approved maintenance.',
            'containment': 'Preserve remaining telemetry, isolate host if compromise is suspected, and collect forensic image where possible.',
            'steps': [
                ('Triage', 'Confirm log tampering', 'Identify whether the event is 1102, 1101, 1100, or service stop and capture host/time.', None, 'evidence'),
                ('Investigation', 'Find preceding activity', 'Look for privileged logons, process creation, or account changes before the log gap.', None, 'evidence'),
                ('Investigation', 'Query remaining events', 'Collect recent System and Security logs before they roll over.', 'Get-WinEvent -LogName Security -MaxEvents 100 | Format-List TimeCreated,Id,ProviderName,Message', 'command'),
                ('Containment', 'Preserve and isolate', 'If suspicious, isolate the host and preserve disk, memory, and remaining logs.', None, 'containment'),
                ('Escalation', 'Incident escalation', 'Notify incident lead because log clearing reduces investigation confidence.', None, 'escalation'),
            ],
        },
        {
            'slug': 'defender-malware-tampering',
            'name': 'Defender Malware or Tampering Response',
            'summary': 'Investigate Microsoft Defender detections, failed remediation, and attempts to disable real-time protection.',
            'category': 'Endpoint Defense',
            'severity': 'critical',
            'event_ids': [1116, 1117, 1118, 1119, 2004, 2001],
            'rule_names': ['Malware Detected (1116)', 'Defender Action Taken (1117)', 'Defender Action Failed (1118)', 'Defender Remediated (1119)', 'Defender Real-time Disabled (2004)', 'Defender Definition Update Failed (2001)'],
            'mitre_tactics': ['Defense Evasion', 'Execution'],
            'mitre_techniques': ['T1562.001 Impair Defenses'],
            'evidence_items': ['Threat name', 'File path', 'Action result', 'User', 'Real-time protection state'],
            'escalation': 'Escalate if Defender failed remediation, was disabled, or malware appears on multiple hosts.',
            'containment': 'Isolate infected host, run full scan, restore Defender settings, and collect malware path/hash.',
            'steps': [
                ('Triage', 'Determine action outcome', 'Check whether Defender detected, remediated, failed, or was disabled.', None, 'evidence'),
                ('Investigation', 'Check Defender status', 'Verify real-time protection, signatures, and last scan status.', 'Get-MpComputerStatus | Select AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,FullScanAge,QuickScanAge', 'command'),
                ('Investigation', 'Review detections', 'Collect recent Defender threat history.', 'Get-MpThreatDetection | Select-Object -First 20 | Format-List *', 'command'),
                ('Containment', 'Isolate if active threat', 'If malware remains active or remediation failed, isolate the endpoint.', None, 'containment'),
                ('Recovery', 'Restore protection', 'Update signatures, run full scan, and verify Defender policy was not tampered with.', None, 'manual'),
            ],
        },
        {
            'slug': 'credential-theft-lolbins',
            'name': 'Credential Theft or LOLBin Execution',
            'summary': 'Respond to Mimikatz keywords, credential dumping strings, and suspicious use of CertUtil, BITSAdmin, WMIC, or Mshta.',
            'category': 'Credential Theft',
            'severity': 'critical',
            'event_ids': [4688, 4104],
            'rule_names': ['Mimikatz Keyword', 'LSA Secrets Dump (sekurlsa)', 'Domain Hash Dump (lsadump)', 'CertUtil Decode (LOLBin)', 'BITSAdmin Transfer (LOLBin)', 'WMIC Remote Process Create', 'Mshta Execution'],
            'mitre_tactics': ['Credential Access', 'Defense Evasion', 'Execution'],
            'mitre_techniques': ['T1003 OS Credential Dumping', 'T1218 System Binary Proxy Execution'],
            'evidence_items': ['Process command line', 'Parent process', 'User context', 'Target host', 'Downloaded file or remote URL'],
            'escalation': 'Escalate immediately if credential dumping strings or remote execution appear in admin context.',
            'containment': 'Isolate the host, rotate exposed credentials, and block involved hashes, domains, or IPs.',
            'steps': [
                ('Triage', 'Preserve process evidence', 'Capture raw process command, parent process, user, host, and time.', None, 'evidence'),
                ('Investigation', 'Identify tool behavior', 'Classify whether this is credential dumping, file transfer, script proxy execution, or remote process creation.', None, 'manual'),
                ('Investigation', 'Search related processes', 'Review recent process creation events around the detection time.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4688} -MaxEvents 100 | Format-List TimeCreated,Message', 'command'),
                ('Containment', 'Contain credential risk', 'Isolate the endpoint and rotate credentials used on the host.', None, 'containment'),
                ('Escalation', 'Credential incident escalation', 'Escalate to incident lead if any secrets, hashes, LSASS access, or admin tokens are implicated.', None, 'escalation'),
            ],
        },
        {
            'slug': 'unexpected-shutdown',
            'name': 'Unexpected System Shutdown Investigation',
            'summary': 'Investigate unexpected shutdowns that may indicate tampering, crash, power event, or forced reboot after malicious activity.',
            'category': 'Availability',
            'severity': 'high',
            'event_ids': [6008, 6006],
            'rule_names': ['Unexpected System Shutdown (6008)', 'EventLog Service Stopped (6006)'],
            'mitre_tactics': ['Impact', 'Defense Evasion'],
            'mitre_techniques': ['T1529 System Shutdown/Reboot'],
            'evidence_items': ['Host', 'Shutdown time', 'Preceding errors', 'User initiated reboot evidence', 'Recent software changes'],
            'escalation': 'Escalate if shutdown follows suspicious logon, service install, log clearing, or malware detection.',
            'containment': 'Keep host online for evidence collection if compromise is suspected and avoid wiping volatile evidence.',
            'steps': [
                ('Triage', 'Confirm timeline', 'Record the unexpected shutdown time and identify events immediately before it.', None, 'evidence'),
                ('Investigation', 'Review system events', 'Look for kernel power, service failures, patching, or manual reboot indicators.', 'Get-WinEvent -LogName System -MaxEvents 100 | Format-List TimeCreated,Id,ProviderName,Message', 'command'),
                ('Investigation', 'Correlate security alerts', 'Check whether the host had privileged logons, PowerShell, Defender, or log evasion alerts before shutdown.', None, 'evidence'),
                ('Escalation', 'Escalate suspicious sequence', 'Escalate if the shutdown appears to hide activity or disrupt collection.', None, 'escalation'),
            ],
        },
        {
            'slug': 'account-lifecycle-access-change',
            'name': 'Account Lifecycle and Access Change Review',
            'summary': 'Review account enablement, disablement, unlocks, renames, password changes, and local admin additions for unauthorized access changes.',
            'category': 'Identity',
            'severity': 'medium',
            'event_ids': [4722, 4725, 4767, 4781, 4723],
            'rule_names': ['User Account Enabled (4722)', 'User Account Disabled (4725)', 'Account Unlocked (4767)', 'Account Name Changed (4781)', 'Password Change Attempt (4723)', 'Net User Add Command', 'Net Admin Group Add'],
            'mitre_tactics': ['Persistence', 'Privilege Escalation'],
            'mitre_techniques': ['T1098 Account Manipulation', 'T1136 Create Account'],
            'evidence_items': ['Actor account', 'Target account', 'Change type', 'Host or domain controller', 'Approval ticket'],
            'escalation': 'Escalate if a privileged, dormant, service, or recently compromised account is changed without approval.',
            'containment': 'Revert unauthorized changes, disable rogue accounts, remove admin membership, and rotate affected credentials.',
            'steps': [
                ('Triage', 'Classify the account change', 'Determine whether the event is enable, disable, unlock, rename, password change, or local admin modification.', None, 'evidence'),
                ('Investigation', 'Confirm authorization', 'Compare the actor, target, and time with identity administration requests or helpdesk tickets.', None, 'manual'),
                ('Investigation', 'Review nearby identity activity', 'Look for adjacent account creation, group membership, and successful logon events for the same account.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4720,4722,4723,4725,4767,4781} -MaxEvents 80 | Format-List TimeCreated,Message', 'command'),
                ('Containment', 'Reverse risky access', 'Disable unauthorized accounts, remove local admin membership, and force credential rotation.', None, 'containment'),
                ('Escalation', 'Escalate privileged or unexplained changes', 'Escalate when the change affects admin accounts, service accounts, or systems with sensitive access.', None, 'escalation'),
            ],
        },
        {
            'slug': 'policy-audit-change',
            'name': 'Audit or Domain Policy Change Investigation',
            'summary': 'Investigate audit policy and domain policy changes that may reduce visibility, weaken authentication, or alter security posture.',
            'category': 'Policy',
            'severity': 'high',
            'event_ids': [4719, 4739],
            'rule_names': ['System Audit Policy Changed (4719)', 'Domain Policy Changed (4739)'],
            'mitre_tactics': ['Defense Evasion', 'Privilege Escalation'],
            'mitre_techniques': ['T1562 Impair Defenses', 'T1484 Domain Policy Modification'],
            'evidence_items': ['Changed policy', 'Actor account', 'Domain controller', 'Before/after setting', 'Change approval'],
            'escalation': 'Escalate if auditing is reduced, authentication requirements are weakened, or the actor is not an approved administrator.',
            'containment': 'Restore approved policy baseline, preserve policy change evidence, and rotate credentials if privileged misuse is suspected.',
            'steps': [
                ('Triage', 'Identify the modified policy', 'Capture which audit or domain policy setting changed and who changed it.', None, 'evidence'),
                ('Investigation', 'Validate against baseline', 'Compare current policy with approved baseline and change records.', 'auditpol /get /category:*', 'command'),
                ('Investigation', 'Review privileged activity', 'Check for privileged logons and account changes before and after the policy change.', None, 'evidence'),
                ('Containment', 'Restore policy baseline', 'If unauthorized, restore the known-good policy and monitor for reversion attempts.', None, 'containment'),
                ('Escalation', 'Escalate visibility reduction', 'Escalate immediately if audit logging was disabled or weakened.', None, 'escalation'),
            ],
        },
        {
            'slug': 'network-share-lateral-movement',
            'name': 'Network Share and Lateral Movement Review',
            'summary': 'Investigate network share access or share creation that may indicate data staging, lateral movement, or unauthorized exposure.',
            'category': 'Network',
            'severity': 'medium',
            'event_ids': [5140, 5142],
            'rule_names': ['Network Share Accessed (5140)', 'Network Share Added (5142)'],
            'mitre_tactics': ['Lateral Movement', 'Collection'],
            'mitre_techniques': ['T1021.002 SMB/Windows Admin Shares', 'T1039 Data from Network Shared Drive'],
            'evidence_items': ['Share name/path', 'Accessing account', 'Source host', 'Target host', 'File activity context'],
            'escalation': 'Escalate if admin shares, sensitive paths, unusual source hosts, or new shares are involved.',
            'containment': 'Remove unauthorized shares, restrict permissions, block suspicious source hosts, and preserve file access evidence.',
            'steps': [
                ('Triage', 'Identify share and actor', 'Capture share name, path, account, source, and target host.', None, 'evidence'),
                ('Investigation', 'Review share permissions', 'Check whether permissions expose sensitive data or allow broad access.', 'Get-SmbShare | Select Name,Path,Description | Sort Name', 'command'),
                ('Investigation', 'Correlate with logons', 'Look for successful network logons from the same source around the share activity.', None, 'evidence'),
                ('Containment', 'Restrict unauthorized access', 'Remove rogue shares or tighten ACLs after preserving evidence.', None, 'containment'),
            ],
        },
        {
            'slug': 'process-execution-review',
            'name': 'New Process Creation Review',
            'summary': 'Review Windows process creation events for suspicious command lines, parent-child relationships, and execution context.',
            'category': 'Execution',
            'severity': 'info',
            'event_ids': [4688],
            'rule_names': ['New Process Created (4688)'],
            'mitre_tactics': ['Execution'],
            'mitre_techniques': ['T1059 Command and Scripting Interpreter'],
            'evidence_items': ['Process name', 'Command line', 'Parent process', 'User', 'Host'],
            'escalation': 'Escalate when command lines show encoded scripts, credential tools, suspicious LOLBins, or execution from temp/user-writable paths.',
            'containment': 'Terminate malicious processes and isolate the host only when suspicious execution is confirmed.',
            'steps': [
                ('Triage', 'Capture process context', 'Record process, command line, parent process, user, host, and timestamp.', None, 'evidence'),
                ('Investigation', 'Classify command line', 'Look for suspicious flags, scripts, remote URLs, encoded payloads, or unusual paths.', None, 'manual'),
                ('Investigation', 'Query recent process events', 'Collect nearby process creation events to reconstruct execution chain.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4688} -MaxEvents 100 | Format-List TimeCreated,Message', 'command'),
                ('Escalation', 'Escalate suspicious execution', 'Escalate only if the process context indicates malicious or policy-violating activity.', None, 'escalation'),
            ],
        },
        {
            'slug': 'privilege-object-access',
            'name': 'Sensitive Privilege and Object Access Review',
            'summary': 'Investigate sensitive privilege use and privileged object access that may indicate misuse of elevated rights.',
            'category': 'Privilege',
            'severity': 'medium',
            'event_ids': [4673, 4674],
            'rule_names': ['Sensitive Privilege Use (4673)', 'Privileged Object Access (4674)'],
            'mitre_tactics': ['Privilege Escalation', 'Credential Access'],
            'mitre_techniques': ['T1068 Exploitation for Privilege Escalation', 'T1003 OS Credential Dumping'],
            'evidence_items': ['Privilege used', 'Object accessed', 'Process name', 'Actor account', 'Host'],
            'escalation': 'Escalate if privileges involve credential material, security policy, LSASS, or unexpected admin tooling.',
            'containment': 'Limit the account, stop suspicious process activity, and rotate credentials if privileged misuse is likely.',
            'steps': [
                ('Triage', 'Identify privilege or object', 'Determine which privilege was used or which protected object was accessed.', None, 'evidence'),
                ('Investigation', 'Review process and account context', 'Validate whether the process and user normally perform this privileged action.', None, 'manual'),
                ('Investigation', 'Collect privilege events', 'Review recent 4673 and 4674 events for repetition or suspicious tools.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4673,4674} -MaxEvents 50 | Format-List TimeCreated,Message', 'command'),
                ('Containment', 'Restrict risky privilege use', 'If suspicious, suspend the account, isolate the host, and preserve evidence.', None, 'containment'),
            ],
        },
        {
            'slug': 'network-firewall-block',
            'name': 'Firewall Blocked Connection Review',
            'summary': 'Review Windows Filtering Platform blocked connection events to identify scanning, blocked malware traffic, or policy issues.',
            'category': 'Network',
            'severity': 'medium',
            'event_ids': [5157],
            'rule_names': ['WFP Connection Blocked (5157)'],
            'mitre_tactics': ['Command and Control', 'Discovery'],
            'mitre_techniques': ['T1046 Network Service Discovery', 'T1071 Application Layer Protocol'],
            'evidence_items': ['Source address', 'Destination address', 'Port/protocol', 'Application path', 'Direction'],
            'escalation': 'Escalate if blocked traffic targets suspicious external infrastructure, repeats across hosts, or follows malware/PowerShell alerts.',
            'containment': 'Keep firewall block in place, isolate the host if traffic indicates compromise, and block related indicators upstream.',
            'steps': [
                ('Triage', 'Capture network tuple', 'Record source, destination, port, protocol, direction, and application path.', None, 'evidence'),
                ('Investigation', 'Correlate with endpoint activity', 'Check whether the blocked connection follows suspicious process, PowerShell, or Defender alerts.', None, 'evidence'),
                ('Investigation', 'Review firewall events', 'Collect recent blocked connection events on the host.', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=5157} -MaxEvents 50 | Format-List TimeCreated,Message', 'command'),
                ('Containment', 'Preserve block and investigate host', 'Do not allow the traffic until the process and destination are validated.', None, 'containment'),
            ],
        },
        {
            'slug': 'replay-attack-response',
            'name': 'Replay Attack Investigation',
            'summary': 'Investigate Windows replay attack detections and validate whether authentication material may have been reused maliciously.',
            'category': 'Authentication',
            'severity': 'critical',
            'event_ids': [4649],
            'rule_names': ['Replay Attack Detected (4649)'],
            'mitre_tactics': ['Credential Access', 'Lateral Movement'],
            'mitre_techniques': ['T1550 Use Alternate Authentication Material'],
            'evidence_items': ['Target account', 'Source host', 'Destination host', 'Authentication package', 'Nearby privileged logons'],
            'escalation': 'Escalate immediately because replay activity can indicate credential theft or lateral movement.',
            'containment': 'Rotate affected credentials, isolate source host, and review Kerberos/NTLM activity around the event.',
            'steps': [
                ('Triage', 'Confirm replay event context', 'Capture account, source, destination, and authentication details from the event.', None, 'evidence'),
                ('Investigation', 'Correlate authentication timeline', 'Look for failed logons, successful logons, and privileged logons near the replay detection.', None, 'evidence'),
                ('Containment', 'Protect credentials', 'Rotate affected credentials and isolate suspicious source systems.', None, 'containment'),
                ('Escalation', 'Escalate credential incident', 'Treat confirmed replay as a credential compromise path and escalate to incident lead.', None, 'escalation'),
            ],
        },
    ]

    for pb in playbooks:
        conn.execute("""
            INSERT OR IGNORE INTO playbooks
                (slug,name,summary,category,severity,mitre_tactics,mitre_techniques,
                 event_ids,rule_names,evidence_items,escalation,containment,is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
        """, (
            pb['slug'], pb['name'], pb['summary'], pb['category'], pb['severity'],
            _json_list(pb['mitre_tactics']), _json_list(pb['mitre_techniques']),
            _json_list(pb['event_ids']), _json_list(pb['rule_names']),
            _json_list(pb['evidence_items']), pb['escalation'], pb['containment'],
        ))
        conn.execute("""
            UPDATE playbooks
            SET name=?, summary=?, category=?, severity=?, mitre_tactics=?,
                mitre_techniques=?, event_ids=?, rule_names=?, evidence_items=?,
                escalation=?, containment=?, is_active=1, updated_at=datetime('now')
            WHERE slug=?
        """, (
            pb['name'], pb['summary'], pb['category'], pb['severity'],
            _json_list(pb['mitre_tactics']), _json_list(pb['mitre_techniques']),
            _json_list(pb['event_ids']), _json_list(pb['rule_names']),
            _json_list(pb['evidence_items']), pb['escalation'], pb['containment'],
            pb['slug'],
        ))
        cur = conn.execute("SELECT id FROM playbooks WHERE slug=?", (pb['slug'],))
        playbook_id = cur.fetchone()[0]
        for idx, (phase, title, detail, command, step_type) in enumerate(pb['steps'], start=1):
            conn.execute("""
                INSERT OR IGNORE INTO playbook_steps
                    (playbook_id,step_order,phase,title,detail,command,step_type)
                VALUES (?,?,?,?,?,?,?)
            """, (playbook_id, idx, phase, title, detail, command, step_type))


def upsert_agent(conn, agent_id, hostname, ip_agent, os_type='windows'):
    cur = conn.cursor()
    cur.execute("SELECT id FROM agents WHERE agent_id=? AND hostname=?", (agent_id, hostname))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE agents SET last_seen=datetime('now'), ip_agent=?, is_active=1 WHERE id=?",
            (ip_agent, row[0])
        )
    else:
        cur.execute(
            "INSERT INTO agents (agent_id,hostname,ip_agent,os_type) VALUES (?,?,?,?)",
            (agent_id, hostname, ip_agent, os_type)
        )
        print(f"  New agent registered: {agent_id} / {hostname} ({ip_agent})")


# =============================================================
# WINDOWS AGENT JSON PARSER
# Only payloads with raw_log + agent_id + hostname are accepted.
# =============================================================
def parse_windows_agent_json(payload_str: str):
    try:
        data = json.loads(payload_str)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    # Strict validation — must come from the Windows SIEM Agent
    if 'raw_log' not in data or 'agent_id' not in data or 'hostname' not in data:
        return None

    # Handle both ip_agent (lowercase, final version) and IP_AGENT (uppercase, older builds)
    ip_agent = (
        data.get('ip_agent') or
        data.get('IP_AGENT') or
        '0.0.0.0'
    )
    if ip_agent in ('unknown', '', None):
        ip_agent = '0.0.0.0'

    # event_id and level may be top-level (agent v4.2+) or need XML extraction
    event_id = data.get('event_id')
    level    = data.get('level')

    raw_log = data.get('raw_log', '')
    if (event_id is None or level is None) and raw_log:
        event_id, level = _extract_from_xml(raw_log, event_id, level)

    return {
        'agent_id':        str(data.get('agent_id', 'unknown')),
        'hostname':        str(data.get('hostname', 'unknown')),
        'os_type':         str(data.get('os_type', 'windows')),
        'source_type':     str(data.get('source_type', 'unknown')),
        'ip_agent':        ip_agent,
        'event_timestamp': data.get('timestamp', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')),
        'event_id':        event_id,
        'level':           level,
        'raw_log':         raw_log,
    }


_WIN_NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


def _find_el(parent, tag):
    r = parent.find(f'{{{_WIN_NS}}}{tag}')
    return r if r is not None else parent.find(tag)


def _extract_from_xml(raw_xml, event_id, level):
    try:
        root   = ET.fromstring(raw_xml)
        sys_el = _find_el(root, 'System')
        if sys_el is None:
            return event_id, level
        if event_id is None:
            el = _find_el(sys_el, 'EventID')
            if el is not None and el.text:
                try:
                    event_id = int(el.text)
                except ValueError:
                    pass
        if level is None:
            el = _find_el(sys_el, 'Level')
            if el is not None and el.text:
                try:
                    level = int(el.text)
                except ValueError:
                    pass
    except Exception:
        pass
    return event_id, level


# =============================================================
# DETECTION ENGINE
# =============================================================
def load_rules_if_stale():
    global rules_cache, rules_last_loaded
    now = datetime.now()
    if (now - rules_last_loaded).total_seconds() < RULES_CACHE_TTL:
        return
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "SELECT id,name,condition_type,condition_value,severity FROM rules WHERE is_active=1"
        )
        with rules_lock:
            rules_cache       = cur.fetchall()
            rules_last_loaded = now
        conn.close()
    except Exception as e:
        print(f"  Rules reload error: {e}")


def is_on_cooldown(key: str) -> bool:
    with cooldown_lock:
        last = alert_cooldowns.get(key)
        if last and (datetime.now() - last).total_seconds() < ALERT_COOLDOWN:
            return True
        alert_cooldowns[key] = datetime.now()
    return False


def evaluate_rules(log: dict) -> list:
    matches = []
    event_id    = log.get('event_id')
    source_type = log.get('source_type', '')
    raw_log     = log.get('raw_log', '')

    with rules_lock:
        rules = list(rules_cache)

    for rule_id, name, ctype, cval, severity in rules:
        hit = False
        try:
            if ctype == 'event_id':
                hit = (event_id is not None and str(event_id) == str(cval))
            elif ctype == 'source_type':
                hit = (source_type == cval)
            elif ctype == 'raw_log_contains':
                hit = bool(cval) and (cval.lower() in raw_log.lower())
        except Exception:
            pass

        if hit:
            key = f"{rule_id}_{log.get('agent_id', '')}_{event_id}"
            if not is_on_cooldown(key):
                matches.append((name, severity))

    return matches


# =============================================================
# EVENT PROCESSOR
# =============================================================
def process_event(payload_str: str):
    conn = None
    try:
        log = parse_windows_agent_json(payload_str)
        if log is None:
            return  # silently drop non-agent payloads

        conn = get_conn()
        cur  = conn.cursor()

        # Track agent
        upsert_agent(conn, log['agent_id'], log['hostname'], log['ip_agent'], log['os_type'])

        # Insert into windows_logs
        cur.execute("""
            INSERT INTO windows_logs
                (agent_id, hostname, ip_agent, source_type, event_id, level,
                 event_timestamp, raw_log)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            log['agent_id'], log['hostname'], log['ip_agent'], log['source_type'],
            log['event_id'], log['level'], log['event_timestamp'], log['raw_log']
        ))
        log_id = cur.lastrowid

        # Run detection rules
        matches   = evaluate_rules(log)
        rule_tags = [name for name, _ in matches]

        if rule_tags:
            cur.execute(
                "UPDATE windows_logs SET rule_tags=? WHERE id=?",
                (json.dumps(rule_tags), log_id)
            )

        for rule_name, severity in matches:
            cur.execute(
                "INSERT INTO alerts (log_id,rule_name,severity) VALUES (?,?,?)",
                (log_id, rule_name, severity)
            )
            with stats_lock:
                stats['alerts'] += 1

        conn.commit()
        with stats_lock:
            stats['received'] += 1

        eid = str(log['event_id']) if log['event_id'] is not None else '????'
        alt = f"  *** {len(matches)} ALERT(S)" if matches else ""
        print(f"  [{stats['received']:05d}] [{eid:<4}] {log['hostname']:<18} {log['source_type']}{alt}")

    except Exception as e:
        print(f"  Process error: {e}")
        with stats_lock:
            stats['errors'] += 1
    finally:
        if conn:
            conn.close()


def worker(payload_str: str):
    load_rules_if_stale()
    process_event(payload_str)


# =============================================================
# LISTENERS
# =============================================================
def udp_listener(port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_BUFFER_SIZE)
    srv.bind(('0.0.0.0', port))
    print(f"  UDP listener on :{port}")
    while True:
        try:
            data, _ = srv.recvfrom(UDP_BUFFER_SIZE)
            threading.Thread(
                target=worker,
                args=(data.decode('utf-8', errors='replace'),),
                daemon=True
            ).start()
        except Exception as e:
            print(f"  UDP error :{port}: {e}")


def handle_tcp_client(conn_sock, addr):
    buf = ''
    conn_sock.settimeout(60)
    try:
        while True:
            try:
                chunk = conn_sock.recv(TCP_BUFFER_SIZE)
                if not chunk:
                    break
                buf += chunk.decode('utf-8', errors='replace')
                while '\n' in buf:
                    line, buf = buf.split('\n', 1)
                    line = line.strip()
                    if line:
                        worker(line)
            except socket.timeout:
                if buf.strip():
                    worker(buf.strip())
                    buf = ''
    except Exception as e:
        print(f"  TCP error ({addr}): {e}")
    finally:
        for line in buf.splitlines():
            if line.strip():
                worker(line.strip())
        conn_sock.close()


def tcp_listener(port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(50)
    print(f"  TCP listener on :{port}")
    while True:
        try:
            cs, addr = srv.accept()
            threading.Thread(
                target=handle_tcp_client,
                args=(cs, addr),
                daemon=True
            ).start()
        except Exception as e:
            print(f"  TCP accept error: {e}")


# =============================================================
# AUTH ROUTES
# =============================================================
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        password  = request.form.get('password', '')
        client_ip = request.remote_addr
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "SELECT id,username,password_hash,role FROM users WHERE username=? AND is_active=1",
            (username,)
        )
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.permanent  = True
            session['user_id'] = user['id']
            session['username']= user['username']
            session['role']    = user['role']
            cur.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user['id'],))
            cur.execute(
                "INSERT INTO login_attempts (username,ip_address,success) VALUES (?,?,1)",
                (username, client_ip)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard'))
        cur.execute(
            "INSERT INTO login_attempts (username,ip_address,success) VALUES (?,?,0)",
            (username, client_ip)
        )
        conn.commit()
        conn.close()
        error = 'Invalid username or password'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',
                           username=session.get('username'),
                           role=session.get('role'))


# =============================================================
# REST API
# =============================================================
@app.route('/api/stats')
@login_required
def api_stats():
    conn = get_conn()
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) FROM windows_logs")
    total_events = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM windows_logs WHERE source_type LIKE 'windows_security%'")
    access = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('high','critical')")
    threat = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM windows_logs WHERE source_type='windows_defender_operational'")
    audit = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM windows_logs WHERE source_type LIKE 'windows_powershell%'")
    endpoint = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM agents WHERE is_active=1")
    active_agents = c.fetchone()[0]
    conn.close()
    return jsonify(
        access=access, threat=threat, audit=audit, endpoint=endpoint,
        total_events=total_events, total_alerts=total_alerts, active_agents=active_agents
    )


MONTHLY_RANGES = {
    '1m':  {'months': 1,  'grain': 'day'},
    '3m':  {'months': 3,  'grain': 'day'},
    '6m':  {'months': 6,  'grain': 'week'},
    '9m':  {'months': 9,  'grain': 'week'},
    '12m': {'months': 12, 'grain': 'month'},
}


def add_months(dt, months):
    month = dt.month - 1 + months
    year = dt.year + month // 12
    month = month % 12 + 1
    last_day = [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
                31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    return dt.replace(year=year, month=month, day=min(dt.day, last_day))


def iter_time_buckets(start_dt, end_dt, grain):
    cur = start_dt.date()
    end = end_dt.date()

    if grain == 'week':
        cur = cur - timedelta(days=cur.weekday())
        while cur <= end:
            yield cur.strftime('%Y-%m-%d'), cur.strftime('%b %d')
            cur += timedelta(days=7)
        return

    if grain == 'month':
        cur = cur.replace(day=1)
        while cur <= end:
            yield cur.strftime('%Y-%m-01'), cur.strftime('%b %Y')
            next_month = add_months(datetime(cur.year, cur.month, 1), 1).date()
            cur = next_month
        return

    while cur <= end:
        yield cur.strftime('%Y-%m-%d'), cur.strftime('%b %d')
        cur += timedelta(days=1)


@app.route('/api/events_over_time')
@login_required
def api_events_over_time():
    range_key = request.args.get('range', '3m')
    cfg = MONTHLY_RANGES.get(range_key, MONTHLY_RANGES['3m'])
    months = cfg['months']
    grain = cfg['grain']

    if grain == 'week':
        bucket_expr = """
            date(
                event_timestamp,
                printf('-%d days', (CAST(strftime('%w', event_timestamp) AS INTEGER) + 6) % 7)
            )
        """
    elif grain == 'month':
        bucket_expr = "strftime('%Y-%m-01', event_timestamp)"
    else:
        bucket_expr = "date(event_timestamp)"

    now = datetime.utcnow()
    if grain == 'month':
        start = add_months(datetime(now.year, now.month, 1), -(months - 1))
    else:
        start = add_months(now, -months)

    conn  = get_conn()
    c     = conn.cursor()
    c.execute(f"""
        SELECT
            {bucket_expr} AS bucket,
            COUNT(*) AS cnt
        FROM windows_logs
        WHERE event_timestamp >= ?
        GROUP BY bucket ORDER BY bucket
    """, (start.strftime('%Y-%m-%d %H:%M:%S'),))
    counts = {r[0]: r[1] for r in c.fetchall()}
    conn.close()

    buckets = [
        {'time': key, 'label': label, 'count': counts.get(key, 0)}
        for key, label in iter_time_buckets(start, now, grain)
    ]

    return jsonify({
        'range': range_key if range_key in MONTHLY_RANGES else '3m',
        'months': months,
        'grain': grain,
        'buckets': buckets,
    })


@app.route('/api/summary')
@login_required
def api_summary():
    conn = get_conn()
    c    = conn.cursor()
    c.execute("""
        SELECT rule_name, severity, COUNT(*) AS cnt
        FROM alerts
        GROUP BY rule_name, severity ORDER BY cnt DESC LIMIT 25
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{'rule': r[0], 'severity': r[1], 'events': r[2]} for r in rows])


@app.route('/api/top_ips')
@login_required
def api_top_ips():
    conn = get_conn()
    c    = conn.cursor()
    c.execute("""
        SELECT ip_agent, COUNT(*) AS cnt FROM windows_logs
        WHERE ip_agent NOT IN ('0.0.0.0','127.0.0.1','::1')
          AND ip_agent IS NOT NULL AND ip_agent != ''
        GROUP BY ip_agent ORDER BY cnt DESC LIMIT 20
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{'ip': r[0], 'count': r[1]} for r in rows])


@app.route('/api/log_types')
@login_required
def api_log_types():
    conn = get_conn()
    c    = conn.cursor()
    c.execute("""
        SELECT COALESCE(source_type,'unknown') AS lt, COUNT(*) AS cnt
        FROM windows_logs GROUP BY lt ORDER BY cnt DESC LIMIT 12
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{'type': r[0] or 'unknown', 'count': r[1]} for r in rows])


@app.route('/api/alerts')
@login_required
def api_alerts():
    limit = request.args.get('limit', 50, type=int)
    conn  = get_conn()
    c     = conn.cursor()
    c.execute("""
        SELECT a.id, a.rule_name, a.severity, a.triggered_at, a.disposition,
               l.ip_agent, l.hostname, l.agent_id, l.source_type, l.event_id
        FROM alerts a
        JOIN windows_logs l ON a.log_id = l.id
        ORDER BY a.triggered_at DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id': r[0], 'threat': r[1], 'severity': r[2], 'time': r[3],
        'disposition': r[4], 'ip_agent': r[5], 'hostname': r[6],
        'agent_id': r[7], 'source_type': r[8], 'event_id': r[9]
    } for r in rows])


@app.route('/api/agents')
@login_required
def api_agents():
    conn = get_conn()
    c    = conn.cursor()
    c.execute("""
        SELECT id, agent_id, hostname, ip_agent, os_type, is_active, first_seen, last_seen
        FROM agents ORDER BY last_seen DESC
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id': r[0], 'agent_id': r[1], 'hostname': r[2], 'ip': r[3],
        'os': r[4], 'active': r[5], 'first_seen': r[6], 'last_seen': r[7]
    } for r in rows])


@app.route('/api/rules')
@login_required
def api_rules():
    conn = get_conn()
    c    = conn.cursor()
    c.execute("""
        SELECT id, name, condition_type, severity, is_active, created_at
        FROM rules ORDER BY severity, name
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id': r[0], 'name': r[1], 'type': r[2],
        'severity': r[3], 'active': r[4], 'created_at': r[5]
    } for r in rows])


def _load_json_list(value):
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except (TypeError, ValueError):
        return []


def _serialize_playbook(row, include_steps=False, steps=None, run=None):
    pb = {
        'id': row['id'],
        'slug': row['slug'],
        'name': row['name'],
        'summary': row['summary'],
        'category': row['category'],
        'severity': row['severity'],
        'mitre_tactics': _load_json_list(row['mitre_tactics']),
        'mitre_techniques': _load_json_list(row['mitre_techniques']),
        'event_ids': _load_json_list(row['event_ids']),
        'rule_names': _load_json_list(row['rule_names']),
        'evidence_items': _load_json_list(row['evidence_items']),
        'escalation': row['escalation'],
        'containment': row['containment'],
        'active': bool(row['is_active']),
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    }
    if 'step_count' in row.keys():
        pb['step_count'] = row['step_count']
    if include_steps:
        pb['steps'] = steps or []
    if run:
        pb['run'] = run
    return pb


def _rank_playbook(alert_rule, event_id, playbooks):
    alert_rule_l = (alert_rule or '').lower()
    event_id_s = str(event_id) if event_id is not None else ''
    best = None
    best_score = 0
    for pb in playbooks:
        score = 0
        event_ids = [str(x) for x in _load_json_list(pb['event_ids'])]
        rule_names = [str(x).lower() for x in _load_json_list(pb['rule_names'])]
        if event_id_s and event_id_s in event_ids:
            score += 60
        for rule_name in rule_names:
            if alert_rule_l == rule_name:
                score += 100
            elif alert_rule_l and (alert_rule_l in rule_name or rule_name in alert_rule_l):
                score += 40
        if score > best_score:
            best = pb
            best_score = score
    return best, best_score


def _playbook_rule_coverage(conn):
    c = conn.cursor()
    c.execute("SELECT name FROM rules WHERE is_active=1 ORDER BY name")
    rules = [r[0] for r in c.fetchall()]

    c.execute("SELECT rule_names FROM playbooks WHERE is_active=1")
    linked = set()
    for row in c.fetchall():
        linked.update(str(v) for v in _load_json_list(row[0]))

    covered = [r for r in rules if r in linked]
    missing = [r for r in rules if r not in linked]
    total = len(rules)
    return {
        'total_rules': total,
        'covered_rules': len(covered),
        'missing_rules': len(missing),
        'coverage_percent': round((len(covered) / total) * 100, 1) if total else 100,
        'missing': missing,
    }


@app.route('/api/playbooks')
@login_required
def api_playbooks():
    q = (request.args.get('q') or '').strip().lower()
    category = (request.args.get('category') or '').strip()
    severity = (request.args.get('severity') or '').strip()

    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT p.*, COUNT(s.id) AS step_count
        FROM playbooks p
        LEFT JOIN playbook_steps s ON s.playbook_id = p.id
        WHERE p.is_active=1
        GROUP BY p.id
        ORDER BY
          CASE p.severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
            WHEN 'low' THEN 4 ELSE 5
          END,
          p.category,
          p.name
    """)
    rows = c.fetchall()
    conn.close()

    items = [_serialize_playbook(r) for r in rows]
    if q:
        items = [
            p for p in items
            if q in ' '.join([
                p['name'], p['summary'], p['category'],
                ' '.join(map(str, p['event_ids'])),
                ' '.join(p['rule_names']),
                ' '.join(p['mitre_techniques']),
            ]).lower()
        ]
    if category:
        items = [p for p in items if p['category'] == category]
    if severity:
        items = [p for p in items if p['severity'] == severity]

    categories = sorted({p['category'] for p in items})
    conn = get_conn()
    coverage = _playbook_rule_coverage(conn)
    conn.close()

    return jsonify({'playbooks': items, 'categories': categories, 'coverage': coverage})


@app.route('/api/playbooks/coverage')
@login_required
def api_playbook_coverage():
    conn = get_conn()
    coverage = _playbook_rule_coverage(conn)
    conn.close()
    return jsonify(coverage)


@app.route('/api/playbooks/<int:playbook_id>')
@login_required
def api_playbook_detail(playbook_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM playbooks WHERE id=? AND is_active=1", (playbook_id,))
    pb = c.fetchone()
    if not pb:
        conn.close()
        return jsonify({'error': 'playbook not found'}), 404

    c.execute("""
        SELECT id, step_order, phase, title, detail, command, step_type
        FROM playbook_steps
        WHERE playbook_id=?
        ORDER BY step_order
    """, (playbook_id,))
    steps = [{
        'id': r[0], 'order': r[1], 'phase': r[2], 'title': r[3],
        'detail': r[4], 'command': r[5], 'type': r[6]
    } for r in c.fetchall()]
    conn.close()
    return jsonify(_serialize_playbook(pb, include_steps=True, steps=steps))


@app.route('/api/playbooks/match')
@login_required
def api_playbook_match():
    alert_id = request.args.get('alert_id', type=int)
    if not alert_id:
        return jsonify({'error': 'alert_id is required'}), 400

    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT a.id, a.rule_name, a.severity, a.triggered_at, a.disposition,
               l.hostname, l.ip_agent, l.agent_id, l.source_type, l.event_id
        FROM alerts a
        JOIN windows_logs l ON l.id = a.log_id
        WHERE a.id=?
    """, (alert_id,))
    alert = c.fetchone()
    if not alert:
        conn.close()
        return jsonify({'error': 'alert not found'}), 404

    c.execute("SELECT * FROM playbooks WHERE is_active=1")
    playbooks = c.fetchall()
    best, score = _rank_playbook(alert['rule_name'], alert['event_id'], playbooks)
    conn.close()

    alert_json = {
        'id': alert['id'],
        'threat': alert['rule_name'],
        'severity': alert['severity'],
        'time': alert['triggered_at'],
        'disposition': alert['disposition'],
        'hostname': alert['hostname'],
        'ip_agent': alert['ip_agent'],
        'agent_id': alert['agent_id'],
        'source_type': alert['source_type'],
        'event_id': alert['event_id'],
    }
    return jsonify({
        'alert': alert_json,
        'match_score': score,
        'playbook': _serialize_playbook(best) if best else None,
    })


@app.route('/api/playbook-runs', methods=['GET'])
@login_required
def api_playbook_runs():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT r.id, r.playbook_id, p.name, p.category, p.severity,
               r.alert_id, r.status, r.started_at, r.completed_at,
               u.username,
               SUM(CASE WHEN rs.is_done=1 THEN 1 ELSE 0 END) AS done_steps,
               COUNT(rs.id) AS total_steps
        FROM playbook_runs r
        JOIN playbooks p ON p.id = r.playbook_id
        LEFT JOIN users u ON u.id = r.started_by
        LEFT JOIN playbook_run_steps rs ON rs.run_id = r.id
        GROUP BY r.id
        ORDER BY r.started_at DESC
        LIMIT 50
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id': r[0], 'playbook_id': r[1], 'playbook_name': r[2],
        'category': r[3], 'severity': r[4], 'alert_id': r[5],
        'status': r[6], 'started_at': r[7], 'completed_at': r[8],
        'started_by': r[9], 'done_steps': r[10] or 0, 'total_steps': r[11] or 0,
    } for r in rows])


@app.route('/api/playbook-runs', methods=['POST'])
@login_required
def api_start_playbook_run():
    body = request.get_json(silent=True) or {}
    playbook_id = body.get('playbook_id')
    alert_id = body.get('alert_id')
    notes = (body.get('notes') or '').strip() or None

    conn = get_conn()
    c = conn.cursor()

    if not playbook_id and alert_id:
        c.execute("""
            SELECT a.rule_name, l.event_id
            FROM alerts a JOIN windows_logs l ON l.id = a.log_id
            WHERE a.id=?
        """, (alert_id,))
        alert = c.fetchone()
        if not alert:
            conn.close()
            return jsonify({'error': 'alert not found'}), 404
        c.execute("SELECT * FROM playbooks WHERE is_active=1")
        best, _ = _rank_playbook(alert['rule_name'], alert['event_id'], c.fetchall())
        if best:
            playbook_id = best['id']

    if not playbook_id:
        conn.close()
        return jsonify({'error': 'playbook_id is required'}), 400

    c.execute("SELECT id FROM playbooks WHERE id=? AND is_active=1", (playbook_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'playbook not found'}), 404

    c.execute("""
        INSERT INTO playbook_runs (playbook_id, alert_id, started_by, notes)
        VALUES (?,?,?,?)
    """, (playbook_id, alert_id, session.get('user_id'), notes))
    run_id = c.lastrowid

    c.execute("SELECT id FROM playbook_steps WHERE playbook_id=? ORDER BY step_order", (playbook_id,))
    for row in c.fetchall():
        c.execute(
            "INSERT INTO playbook_run_steps (run_id, step_id) VALUES (?,?)",
            (run_id, row['id'])
        )

    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'run_id': run_id, 'playbook_id': playbook_id}), 201


@app.route('/api/playbook-runs/<int:run_id>')
@login_required
def api_playbook_run_detail(run_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT r.*, p.name, p.summary, p.category, p.severity, u.username
        FROM playbook_runs r
        JOIN playbooks p ON p.id = r.playbook_id
        LEFT JOIN users u ON u.id = r.started_by
        WHERE r.id=?
    """, (run_id,))
    run = c.fetchone()
    if not run:
        conn.close()
        return jsonify({'error': 'run not found'}), 404

    c.execute("""
        SELECT rs.id, rs.step_id, rs.is_done, rs.analyst_notes, rs.completed_at,
               s.step_order, s.phase, s.title, s.detail, s.command, s.step_type
        FROM playbook_run_steps rs
        JOIN playbook_steps s ON s.id = rs.step_id
        WHERE rs.run_id=?
        ORDER BY s.step_order
    """, (run_id,))
    steps = [{
        'run_step_id': r[0], 'step_id': r[1], 'done': bool(r[2]),
        'notes': r[3], 'completed_at': r[4], 'order': r[5], 'phase': r[6],
        'title': r[7], 'detail': r[8], 'command': r[9], 'type': r[10],
    } for r in c.fetchall()]
    conn.close()
    return jsonify({
        'id': run['id'],
        'playbook_id': run['playbook_id'],
        'alert_id': run['alert_id'],
        'status': run['status'],
        'notes': run['notes'],
        'started_at': run['started_at'],
        'completed_at': run['completed_at'],
        'started_by': run['username'],
        'playbook_name': run['name'],
        'summary': run['summary'],
        'category': run['category'],
        'severity': run['severity'],
        'steps': steps,
    })


@app.route('/api/playbook-runs/<int:run_id>/cancel', methods=['PATCH'])
@login_required
def api_cancel_playbook_run(run_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT status FROM playbook_runs WHERE id=?", (run_id,))
    run = c.fetchone()
    if not run:
        conn.close()
        return jsonify({'error': 'run not found'}), 404
    if run['status'] == 'completed':
        conn.close()
        return jsonify({'error': 'completed runs cannot be cancelled'}), 409

    c.execute("""
        UPDATE playbook_runs
        SET status='cancelled', completed_at=datetime('now')
        WHERE id=?
    """, (run_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'status': 'cancelled'})


@app.route('/api/playbook-runs/<int:run_id>/steps/<int:step_id>', methods=['PATCH'])
@login_required
def api_update_playbook_run_step(run_id, step_id):
    body = request.get_json(silent=True) or {}
    is_done = 1 if body.get('done') else 0
    notes = (body.get('notes') or '').strip() or None

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT status FROM playbook_runs WHERE id=?", (run_id,))
    run = c.fetchone()
    if not run:
        conn.close()
        return jsonify({'error': 'run not found'}), 404
    if run['status'] == 'cancelled':
        conn.close()
        return jsonify({'error': 'cancelled runs cannot be updated'}), 409

    c.execute("""
        UPDATE playbook_run_steps
        SET is_done=?, analyst_notes=?,
            completed_at=CASE WHEN ?=1 THEN datetime('now') ELSE NULL END
        WHERE run_id=? AND step_id=?
    """, (is_done, notes, is_done, run_id, step_id))
    if c.rowcount == 0:
        conn.close()
        return jsonify({'error': 'run step not found'}), 404

    c.execute("""
        SELECT
          SUM(CASE WHEN is_done=1 THEN 1 ELSE 0 END) AS done_steps,
          COUNT(*) AS total_steps
        FROM playbook_run_steps WHERE run_id=?
    """, (run_id,))
    progress = c.fetchone()
    done_steps = progress['done_steps'] or 0
    total_steps = progress['total_steps'] or 0
    status = 'completed' if total_steps and done_steps == total_steps else 'in_progress'
    c.execute("""
        UPDATE playbook_runs
        SET status=?, completed_at=CASE WHEN ?='completed' THEN datetime('now') ELSE NULL END
        WHERE id=?
    """, (status, status, run_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'status': status, 'done_steps': done_steps, 'total_steps': total_steps})


@app.route('/api/server_stats')
@login_required
def api_server_stats():
    with stats_lock:
        return jsonify(dict(stats))


@app.route('/api/recent_logs')
@login_required
def api_recent_logs():
    limit = request.args.get('limit', 50, type=int)
    conn  = get_conn()
    c     = conn.cursor()
    c.execute("""
        SELECT
            l.id,
            l.agent_id,
            l.hostname,
            l.ip_agent,
            l.source_type,
            l.event_id,
            l.level,
            l.event_timestamp,
            l.server_receive_time,
            l.raw_log,
            l.rule_tags,
            CASE WHEN EXISTS (SELECT 1 FROM alerts a WHERE a.log_id=l.id) THEN 1 ELSE 0 END
        FROM windows_logs l
        ORDER BY l.id DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id':          r[0],
        'agent_id':    r[1],
        'hostname':    r[2],
        'ip_agent':    r[3],
        'source_type': r[4],
        'event_id':    r[5],
        'level':       r[6],
        'time':        r[7],
        'received':    r[8],
        'raw_log':     r[9],
        'rule_tags':   json.loads(r[10]) if r[10] else [],
        'has_alert':   r[11],
    } for r in rows])


@app.route('/api/users', methods=['GET'])
@login_required
def api_users():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    conn = get_conn()
    c    = conn.cursor()
    c.execute("SELECT id,username,email,role,is_active,created_at,last_login FROM users ORDER BY id")
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'id': r[0], 'username': r[1], 'email': r[2],
        'role': r[3], 'active': r[4], 'created_at': r[5], 'last_login': r[6]
    } for r in rows])


@app.route('/api/users', methods=['POST'])
@login_required
def api_create_user():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email    = data.get('email', '').strip() or None
    role     = data.get('role', 'analyst')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if role not in ('admin', 'analyst', 'viewer'):
        return jsonify({'error': 'invalid role'}), 400
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
            (username, email, generate_password_hash(password), role)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 409
    conn.close()
    return jsonify({'ok': True, 'username': username}), 201


# =============================================================
# LOCAL AI ASSISTANT (LM Studio — OpenAI-compatible)
# Privacy: all calls go to http://localhost:1234. No cloud APIs.
# =============================================================
def _legacy_call_lmstudio(messages):
    """Deprecated: kept only to avoid breaking old references."""
    payload = {
        "model":       LMSTUDIO_MODEL,
        "messages":    messages,
        "temperature": 0.2,
        "max_tokens":  700,
        "stream":      False,
    }
    try:
        r = requests.post(LMSTUDIO_CHAT_URL, json=payload, timeout=60)
    except requests.exceptions.ConnectionError:
        return False, ("Local AI is offline. Open LM Studio, load "
                       f"{LMSTUDIO_MODEL}, then start the Local Server "
                       "on port 1234.")
    except requests.exceptions.Timeout:
        return False, "Local AI timed out. The model may be busy or too large for your machine."
    except requests.exceptions.RequestException as e:
        return False, f"Local AI request failed: {type(e).__name__}"

    if r.status_code != 200:
        snippet = (r.text or '')[:200]
        return False, f"Local AI returned HTTP {r.status_code}. {snippet}"

    try:
        data = r.json()
        return True, data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError):
        return False, "Local AI returned an unexpected response shape."


def _ollama_model_names():
    r = requests.get(OLLAMA_TAGS_URL, timeout=OLLAMA_STATUS_TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Ollama returned HTTP {r.status_code}.")
    data = r.json() or {}
    models = data.get("models") or []
    return [m.get("name", "") for m in models if isinstance(m, dict)]


def _ai_profile(profile_id=None):
    profile_id = (profile_id or "fast").strip().lower()
    return AI_MODEL_PROFILES.get(profile_id, AI_MODEL_PROFILES["fast"])


def _ai_profiles_payload(installed=None):
    installed = set(installed or [])
    profiles = []
    for profile in AI_MODEL_PROFILES.values():
        p = dict(profile)
        p["installed"] = p["model"] in installed if installed else None
        profiles.append(p)
    return profiles


def call_ollama(messages, profile_id=None):
    """Send chat request to Ollama. Returns (ok: bool, content_or_error: str)."""
    profile = _ai_profile(profile_id)
    model = profile["model"]
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,
        "keep_alive": "10m",
        "options": {
            "temperature": 0.2,
            "num_predict": AI_NUM_PREDICT,
            "num_ctx": AI_NUM_CTX,
        },
    }
    try:
        r = requests.post(OLLAMA_CHAT_URL, json=payload, timeout=OLLAMA_REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError:
        return False, (
            f"Ollama is offline. Start Ollama, then confirm {OLLAMA_BASE_URL} is reachable "
            f"and model {model} is installed."
        )
    except requests.exceptions.Timeout:
        return False, (
            f"Ollama timed out after {OLLAMA_REQUEST_TIMEOUT}s. The model may still be loading, "
            "or your machine may need a smaller model / fewer tokens."
        )
    except requests.exceptions.RequestException as e:
        return False, f"Ollama request failed: {type(e).__name__}"

    if r.status_code == 404:
        return False, f"Ollama model {model} was not found. Run: ollama pull {model}"
    if r.status_code != 200:
        snippet = (r.text or '')[:240]
        return False, f"Ollama returned HTTP {r.status_code}. {snippet}"

    try:
        data = r.json()
        content = data.get("message", {}).get("content", "")
        if not content:
            return False, "Ollama returned an empty response."
        return True, content
    except (ValueError, AttributeError):
        return False, "Ollama returned an unexpected response shape."


def stream_ollama(messages, profile_id=None):
    """Yield Server-Sent Events from Ollama's streaming chat API."""
    profile = _ai_profile(profile_id)
    model = profile["model"]
    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
        "think": False,
        "keep_alive": "10m",
        "options": {
            "temperature": 0.2,
            "num_predict": AI_NUM_PREDICT,
            "num_ctx": AI_NUM_CTX,
        },
    }

    def event(name, data):
        return f"event: {name}\ndata: {json.dumps(data)}\n\n"

    try:
        with requests.post(
            OLLAMA_CHAT_URL,
            json=payload,
            stream=True,
            timeout=(5, OLLAMA_REQUEST_TIMEOUT),
        ) as r:
            if r.status_code == 404:
                yield event("error", {
                    "message": f"Ollama model {model} was not found. Run: ollama pull {model}"
                })
                return
            if r.status_code != 200:
                yield event("error", {
                    "message": f"Ollama returned HTTP {r.status_code}. {(r.text or '')[:240]}"
                })
                return

            yielded = False
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except ValueError:
                    continue
                token = data.get("message", {}).get("content", "")
                if token:
                    yielded = True
                    yield event("token", {"token": token})
                if data.get("done"):
                    break
            yield event("done", {"ok": yielded})
    except requests.exceptions.ConnectionError:
        yield event("error", {
            "message": (
                f"Ollama is offline. Start Ollama, then confirm {OLLAMA_BASE_URL} is reachable "
                f"and model {model} is installed."
            )
        })
    except requests.exceptions.Timeout:
        yield event("error", {
            "message": (
                f"Ollama did not start responding within {OLLAMA_REQUEST_TIMEOUT}s. "
                "Use a smaller local model or reduce the selected context."
            )
        })
    except requests.exceptions.RequestException as e:
        yield event("error", {"message": f"Ollama request failed: {type(e).__name__}"})


def _fetch_siem_context(alert_limit=5, log_limit=50, snippet_chars=120):
    """Compact SIEM context for prompting. Caps raw_log to fit small local models."""
    conn = get_conn()
    c    = conn.cursor()

    c.execute("""
        SELECT a.rule_name, a.severity, l.event_id, l.hostname, l.ip_agent,
               l.source_type, a.triggered_at, a.disposition
        FROM alerts a
        JOIN windows_logs l ON a.log_id = l.id
        ORDER BY a.triggered_at DESC LIMIT ?
    """, (alert_limit,))
    alerts = [{
        'rule_name':    r[0],
        'severity':     r[1],
        'event_id':     r[2],
        'hostname':     r[3],
        'ip_agent':     r[4],
        'source_type':  r[5],
        'triggered_at': r[6],
        'disposition':  r[7],
    } for r in c.fetchall()]

    c.execute("""
        SELECT
            l.id,
            l.event_id,
            l.level,
            l.hostname,
            l.ip_agent,
            l.source_type,
            l.event_timestamp,
            l.rule_tags,
            l.raw_log,
            (
                SELECT COUNT(*)
                FROM alerts a
                WHERE a.log_id = l.id
            ) AS alert_count,
            (
                SELECT a.rule_name
                FROM alerts a
                WHERE a.log_id = l.id
                ORDER BY a.triggered_at DESC
                LIMIT 1
            ) AS alert_rule,
            (
                SELECT a.severity
                FROM alerts a
                WHERE a.log_id = l.id
                ORDER BY a.triggered_at DESC
                LIMIT 1
            ) AS alert_severity,
            (
                SELECT a.triggered_at
                FROM alerts a
                WHERE a.log_id = l.id
                ORDER BY a.triggered_at DESC
                LIMIT 1
            ) AS alert_triggered_at,
            (
                SELECT a.disposition
                FROM alerts a
                WHERE a.log_id = l.id
                ORDER BY a.triggered_at DESC
                LIMIT 1
            ) AS alert_disposition
        FROM windows_logs l
        ORDER BY
            CASE WHEN alert_count > 0 THEN 0 ELSE 1 END,
            COALESCE(alert_triggered_at, l.event_timestamp) DESC,
            l.id DESC
        LIMIT ?
    """, (log_limit,))
    events = []
    for r in c.fetchall():
        snippet = (r[8] or '')
        if len(snippet) > snippet_chars:
            snippet = snippet[:snippet_chars]
        events.append({
            'id':              r[0],
            'event_id':        r[1],
            'level':           r[2],
            'hostname':        r[3],
            'ip_agent':        r[4],
            'source_type':     r[5],
            'event_timestamp': r[6],
            'rule_tags':       json.loads(r[7]) if r[7] else [],
            'raw_snippet':     snippet,
            'is_alert':        bool(r[9]),
            'alert_count':     r[9],
            'alert_rule':      r[10],
            'alert_severity':  r[11],
            'alert_triggered_at': r[12],
            'alert_disposition':  r[13],
        })

    conn.close()
    return {'alerts': alerts, 'logs': events, 'events': events}


@app.route('/api/ai/status')
@login_required
def api_ai_status():
    result = {
        'online':   False,
        'provider': 'Ollama',
        'base_url': OLLAMA_BASE_URL,
        'model':    OLLAMA_MODEL,
        'default_profile': 'fast',
        'profiles': _ai_profiles_payload(),
        'local':    True,
        'message':  '',
    }
    try:
        model_names = _ollama_model_names()
        result['profiles'] = _ai_profiles_payload(model_names)
        available = [p for p in result['profiles'] if p['installed']]
        if available:
            result['online']  = True
            result['model'] = AI_MODEL_PROFILES['fast']['model']
            result['message'] = "Connected to Ollama. Local AI models are available."
        else:
            result['message'] = (
                "Ollama is running but the configured SIEM models are not installed. "
                "Run: ollama pull llama3.2:3b"
            )
    except requests.exceptions.ConnectionError:
        result['message'] = f"Cannot reach Ollama at {OLLAMA_BASE_URL}. Start Ollama first."
    except requests.exceptions.Timeout:
        result['message'] = "Ollama did not respond in time."
    except (requests.exceptions.RequestException, RuntimeError) as e:
        result['message'] = f"Failed to reach Ollama. {str(e)}"
    return jsonify(result)


@app.route('/api/ai/context')
@login_required
def api_ai_context():
    return jsonify(_fetch_siem_context())


@app.route('/api/ai/ask', methods=['POST'])
@login_required
def api_ai_ask():
    body     = request.get_json(silent=True) or {}
    question = (body.get('question') or '').strip()
    mode     = (body.get('mode') or 'general').strip()
    profile  = _ai_profile(body.get('model_profile'))

    if not question:
        return jsonify({'error': 'question is required'}), 400
    if len(question) > AI_MAX_QUESTION_LEN:
        return jsonify({
            'error': f'question too long (max {AI_MAX_QUESTION_LEN} chars)'
        }), 400

    ctx        = _fetch_siem_context(alert_limit=2, log_limit=2, snippet_chars=0)
    ctx_json   = json.dumps(ctx, default=str)

    system_prompt = (
        "You are a local SOC AI assistant inside a SIEM dashboard.\n"
        "You analyze only the provided SIEM context.\n"
        "Do not invent events, IPs, usernames, hostnames, or alerts.\n"
        "If evidence is missing, say that evidence is missing.\n"
        "Give practical defensive guidance only.\n"
        "Keep the answer concise and avoid long explanations.\n"
        "Format the answer with:\n"
        "Summary\n"
        "Risk Level\n"
        "Evidence From SIEM\n"
        "Recommended Next Steps"
    )

    user_content = (
        f"Question: {question}\n"
        f"Mode: {mode}\n\n"
        f"SIEM Context (JSON):\n{ctx_json}"
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_content},
    ]

    ok, content = call_ollama(messages, profile['id'])
    if not ok:
        return jsonify({
            'error':    content,
            'provider': 'Ollama',
            'model':    profile['model'],
            'model_profile': profile,
            'local':    True,
        }), 503

    return jsonify({
        'answer':   content,
        'provider': 'Ollama',
        'model':    profile['model'],
        'model_profile': profile,
        'local':    True,
    })


@app.route('/api/ai/ask_stream', methods=['POST'])
@login_required
def api_ai_ask_stream():
    body     = request.get_json(silent=True) or {}
    question = (body.get('question') or '').strip()
    mode     = (body.get('mode') or 'general').strip()
    profile  = _ai_profile(body.get('model_profile'))

    if not question:
        return jsonify({'error': 'question is required'}), 400
    if len(question) > AI_MAX_QUESTION_LEN:
        return jsonify({
            'error': f'question too long (max {AI_MAX_QUESTION_LEN} chars)'
        }), 400

    ctx      = _fetch_siem_context(alert_limit=1, log_limit=1, snippet_chars=0)
    ctx_json = json.dumps(ctx, default=str)

    system_prompt = (
        "You are a local SOC AI assistant inside a SIEM dashboard. "
        "Use only the provided SIEM context. Do not invent evidence. "
        "Answer in concise sections: Summary, Risk Level, Evidence From SIEM, Recommended Next Steps. "
        "Keep the response short and actionable."
    )
    user_content = (
        f"Question: {question[:AI_MAX_QUESTION_LEN]}\n"
        f"Mode: {mode}\n"
        f"SIEM Context JSON: {ctx_json}"
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_content},
    ]

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "X-SIEM-AI-Model": profile["model"],
        "X-SIEM-AI-Profile": profile["id"],
    }
    return Response(
        stream_with_context(stream_ollama(messages, profile['id'])),
        mimetype="text/event-stream",
        headers=headers,
    )


# =============================================================
# MAIN
# =============================================================
def main():
    print("=" * 60)
    print("  SIEM Dashboard — Windows Agent Receiver")
    print("=" * 60)
    init_db()
    load_rules_if_stale()
    for port in WIN_AGENT_PORTS:
        threading.Thread(target=udp_listener, args=(port,), daemon=True).start()
        threading.Thread(target=tcp_listener, args=(port,), daemon=True).start()
    print(f"\n  Dashboard : http://localhost:{HTTP_PORT}")
    print(f"  Login     : admin / admin123")
    print(f"  UDP :{WIN_AGENT_PORT}   — SIEMAgent.exe (UDP mode)")
    print(f"  TCP :{WIN_AGENT_PORT}   — SIEMAgent.exe (TCP mode)")
    print("  Only Windows Agent JSON envelopes are stored.")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=HTTP_PORT, threaded=True, use_reloader=False)


if __name__ == '__main__':
    main()
