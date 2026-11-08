#!/usr/bin/env python3
"""
NIMROD v1.2 - authorized security testing agent (safe recon + arsenal modes).
Env overrides: NIMROD_API_BASE, NIMROD_API_KEY, NIMROD_MODEL, NIMROD_TIMEOUT,
NIMROD_API_TIMEOUT, NIMROD_THINK=1 (enable model reasoning),
NIMROD_SAFE=1 (read-only mode), NIMROD_SCOPE="hosts/CIDRs you are authorized to test",
NIMROD_JOBS=N (parallel tools, default 4), NIMROD_KEEPALIVE=0 (disable remote warm-up)
"""
import argparse, atexit, gzip, json, os, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.live import Live
from rich.layout import Layout
from rich.markup import escape

try:
    from openai import OpenAI
except ImportError:
    print("[!] Missing dependency. Run: pip install openai rich")
    sys.exit(1)

API_BASE = os.environ.get("NIMROD_API_BASE", "http://localhost:4001/v1")
API_KEY  = os.environ.get("NIMROD_API_KEY", "sk-dummy")
MODEL = os.environ.get("NIMROD_MODEL", "nimrod-brain")
CMD_TIMEOUT = int(os.environ.get("NIMROD_TIMEOUT", "300"))
API_TIMEOUT = float(os.environ.get("NIMROD_API_TIMEOUT", "300"))
THINK = os.environ.get("NIMROD_THINK", "0").lower() in ("1", "true", "yes", "on")
# Ollama-compatible thinking switch; litellm passes it through. Thinking models
# otherwise burn 1000+ hidden tokens (or the whole budget) before answering.
THINK_OPTS = {} if THINK else {"extra_body": {"think": False}}
MAX_OUT = 6000
MAX_CAPTURE_BYTES = 1000000
MAX_CONTEXT_CHARS = 60000
KEEPALIVE_INTERVAL = 240
KEEPALIVE_REMOTE_MODEL = None
MAX_JOBS = int(os.environ.get("NIMROD_JOBS", "4"))
SEQUENTIAL = False

console = Console()

def make_client():
    return OpenAI(base_url=API_BASE, api_key=API_KEY, timeout=API_TIMEOUT, max_retries=1)

client = make_client()

ACTIVE_PROCESSES = {}
ACTIVE_LOCK = threading.Lock()

def _register_process(pid):
    with ACTIVE_LOCK:
        ACTIVE_PROCESSES[pid] = time.time()

def _unregister_process(pid):
    with ACTIVE_LOCK:
        ACTIVE_PROCESSES.pop(pid, None)

def _kill_all_active_processes():
    with ACTIVE_LOCK:
        pids = list(ACTIVE_PROCESSES)
    for pid in pids:
        try:
            os.killpg(pid, signal.SIGKILL)
        except Exception:
            pass

atexit.register(_kill_all_active_processes)

def _termination_signal(signum, frame):
    raise KeyboardInterrupt

for _sig in (signal.SIGTERM, signal.SIGHUP):
    try:
        signal.signal(_sig, _termination_signal)
    except Exception:
        pass

MODE = "PURPLE"
ARSENAL = os.environ.get("NIMROD_SAFE", "0").lower() not in ("1", "true", "yes", "on")
SCOPE = os.environ.get("NIMROD_SCOPE", "")
LAST_INV = {}
MISSION_LOG = []
LAST_PLAN = None
LAST_ABORTED = False

MODES = {
    "RED":    "offensive security (recon, enumeration, vulnerability discovery, exploitation).",
    "BLUE":   "defensive security (log/process/network inspection, forensics, hardening review).",
    "PURPLE": "both offensive and defensive security operations.",
}

# Safe-mode allowlist: passive/read-only inspection and recon only.
WHITELIST = [
    "nmap", "arp-scan", "arp", "ping", "traceroute", "tracepath",
    "whois", "dig", "nslookup", "host", "nikto", "gobuster", "dirb", "masscan",
    "ip", "ifconfig", "netstat", "ss", "lsof", "ps", "uname", "hostname",
    "df", "du", "free", "ls", "cat", "head", "tail", "grep", "awk", "cut",
    "sort", "uniq", "wc", "file", "strings", "xxd", "hexdump",
    "sha256sum", "md5sum", "base64", "python3",
    "tcpdump", "tshark", "searchsploit", "whatweb", "wafw00f",
]

# Full offensive/defensive arsenal, grouped for the inventory display. Only
# tools actually installed on this device are shown to the planner.
SECURITY_TOOLS = {
    "recon": (
        "nmap masscan rustscan arp-scan netdiscover fping dnsenum dnsrecon fierce "
        "whois dig nslookup host traceroute tracepath amass subfinder assetfinder "
        "theHarvester recon-ng wafw00f whatweb httpx nuclei naabu nbtscan onesixtyone "
        "snmpwalk snmp-check ike-scan dnsx katana gau waybackurls hakrawler gospider"
    ),
    "web": (
        "nikto gobuster dirb dirsearch ffuf feroxbuster wpscan sqlmap commix xsstrike "
        "dalfox wapiti zaproxy zap-cli burpsuite curl wget arjun paramspider x8"
    ),
    "exploit": (
        "msfconsole msfvenom msfdb searchsploit exploitdb setoolkit beef-xss "
        "routersploit armitage"
    ),
    "credentials": (
        "hydra medusa patator john hashcat crunch cewl responder mitm6"
    ),
    "active-directory": (
        "impacket-psexec impacket-secretsdump impacket-wmiexec impacket-ntlmrelayx "
        "impacket-smbexec impacket-atexec psexec.py secretsdump.py wmiexec.py "
        "crackmapexec netexec nxc evil-winrm bloodhound-python enum4linux "
        "enum4linux-ng smbclient smbmap rpcclient ldapsearch ldapdomaindump "
        "kerbrute certipy certipy-ad bloodyAD powerview.py targetedKerberoast.py"
    ),
    "wireless": (
        "airmon-ng airodump-ng aireplay-ng aircrack-ng airdecap-ng kismet bettercap "
        "ettercap mitmproxy mdk4 reaver bully wifite macchanger"
    ),
    "network": (
        "tcpdump tshark wireshark zeek suricata ncat nc arpspoof dsniff proxychains4 "
        "proxychains tor responder mitm6 yersinia hping3 chisel ligolo-ng"
    ),
    "forensics": (
        "volatility3 vol.py autopsy fls icat binwalk foremost exiftool scalpel "
        "bulk_extractor"
    ),
    "defensive": (
        "lynis chkrootkit rkhunter clamscan clamdscan aide tripwire osquery auditd"
    ),
}

ALL_SECURITY_TOOLS = sorted({t for names in SECURITY_TOOLS.values() for t in names.split()})

# Commands that can damage or mutate the host itself are blocked in every
# mode. Checked against the first binary of each shell segment, so reading
# /etc/passwd with john/hashcat is fine while running passwd is not.
HOST_DESTRUCTIVE_CMDS = {
    "rm", "unlink", "rmdir", "mkfs", "chmod", "chown", "chattr", "setfacl",
    "systemctl", "service", "kill", "pkill", "killall", "shutdown", "reboot",
    "poweroff", "halt", "useradd", "userdel", "usermod", "groupadd", "groupdel",
    "passwd", "chpasswd", "crontab", "mount", "umount", "fdisk", "parted",
    "wipefs", "shred", "truncate", "modprobe", "insmod", "rmmod", "swapoff",
    "apt", "apt-get", "dpkg", "pip", "pip3", "npm", "dnf", "yum", "pacman",
    "tee", "cp", "mv", "ln", "install", "visudo",
}
HOST_DESTRUCTIVE_PATTERNS = [
    "dd if=", "dd of=", "of=/dev/sd", "of=/dev/nvme",
    "iptables -F", "iptables -X", "iptables --flush", "iptables --delete-chain",
    "nft flush", "ufw disable", "setenforce 0", "sysctl -w",
]
SHELL_ESCAPES = [
    "| sh", "| bash", "| zsh", "| dash", "bash -c", "sh -c", "zsh -c",
    "python3 -c", "python -c", "perl -e", "ruby -e", "php -r",
    "nc -e", "ncat -e", "socat", "$(", "`", "<(", ">(",
]
# Extra restrictions that apply only in safe mode (no writes/downloads).
SAFE_BLOCKED = [
    "wget ", "curl -o", "curl -O", "apt ", "apt-get", "dpkg ",
    "pip install", "pip3 install", "npm ", "git clone",
    " -on", " -ox", " -og", " -oa", "sed -i", "tee ", "mv ", "cp ", "ln -s",
]

REDIRECT_RE = re.compile(r">{1,2}\s*([^\s;|]+)")

TOOLS = [{
    "type": "function",
    "function": {
        "name": "propose_command",
        "description": "Propose a terminal command for human approval. Never execute anything yourself. In arsenal mode any installed security tool may be used; in safe mode commands are read-only. Stay inside the operator's authorized scope.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Exact command to run."},
                "reason":  {"type": "string", "description": "Why this command is needed."}
            },
            "required": ["command", "reason"]
        }
    }
}]

PLAN_SCHEMA = (
    '{"mission_summary": "...", "steps": [{"step": 1, "title": "...", '
    '"command": "...", "purpose": "...", "risk": "low|medium|high", '
    '"depends_on": []}]}'
)

def plan_system():
    if ARSENAL:
        rules = (
            "You are NIMROD's mission planning engine for AUTHORIZED penetration testing. "
            "You receive an OPERATOR DIRECTIVE, an AUTHORIZED SCOPE, and a DEVICE INVENTORY. "
            "Produce a step-by-step mission plan. "
            "Rules: you may use ANY installed security tool; AVAILABLE TOOLS lists the discovered "
            "arsenal, but another installed executable may also be used when the directive names it. "
            "Offensive categories are allowed: reconnaissance, web, exploitation, credential, wireless, "
            "Active Directory, and post-exploitation. Do not stop at reconnaissance when the directive "
            "asks for a full or attack-oriented engagement; include exploitation, credential-access, "
            "AD, and post-exploitation steps using the installed arsenal, within scope. "
            "Only target hosts explicitly inside AUTHORIZED SCOPE; never "
            "invent targets. Prefer the least destructive technique that meets the objective. Do not "
            "plan denial-of-service, destructive data operations, or persistence unless the directive "
            "explicitly requests it. Every command is executed only after operator approval. Use "
            "non-interactive commands that finish on their own; add non-interactive flags where needed "
            "(for example sudo -n). Quote URLs and arguments that contain shell metacharacters. "
            "Keep commands short and single-purpose. "
            "The inventory includes command_timeout_seconds and usable wordlists. Commands are killed "
            "when the timeout expires, so keep every step well inside that budget. Prefer fast scans "
            "(nmap -T4 -F or --top-ports 1000); use -p- only if the directive explicitly demands full "
            "port coverage. For web fuzzing use a preferred small wordlist (for example dirb/common.txt), "
            "never rockyou. For password attacks use the quick user/password lists or a single username, "
            "not exhaustive lists, unless explicitly requested. Use nuclei severity/rate limits. "
            "Avoid daemon or interactive tools (responder, bettercap, msfconsole without -x, wireshark, "
            "burpsuite) unless explicitly requested; use one-shot non-interactive modes. Split scans that "
            "may exceed the timeout into smaller steps. "
            "Independent steps run in parallel up to the configured job limit. Add depends_on as a list "
            "of earlier step numbers when a step needs a prior step's output or file; steps without "
            "depends_on may start immediately. Prefer parallel independent checks. If a later step consumes "
            "a file, the earlier step must write it (for example nmap -oN scan.txt) and the dependent step "
            "must reference that exact file. Never use placeholder tokens like {{step1.output}}; hand off "
            "data through explicit files. Independent steps must use distinct output filenames. Never "
            "create dependency cycles. "
            "Do NOT include reasoning, analysis, or thinking text. "
            "Output ONLY a valid JSON object, no fences, no commentary, exactly: "
        )
    else:
        rules = (
            "You are NIMROD's mission planning engine in SAFE MODE. You receive an OPERATOR "
            "DIRECTIVE and a DEVICE INVENTORY. Produce a step-by-step mission plan. "
            "Rules: use ONLY binaries listed in AVAILABLE TOOLS; every command must be read-only "
            "and non-mutating (the only allowed write is a redirect to a bare .txt report filename "
            "in the CURRENT directory, e.g. audit.txt - never absolute paths and never subdirectories); "
            "order steps logically (discovery -> enumeration -> analysis -> findings); derive subnets "
            "from inventory for network scans; quote URLs and arguments that contain shell metacharacters; "
            "keep commands short and single-purpose; keep each step well inside the inventory's "
            "command_timeout_seconds and prefer fast scans. Independent steps may run in parallel; "
            "add depends_on with earlier step numbers when a step needs a prior result or file. "
            "Independent steps must use distinct output filenames and dependencies must not cycle. "
            "Do NOT include reasoning, analysis, or thinking text. "
            "Output ONLY a valid JSON object, no fences, no commentary, exactly: "
        )
    return rules + PLAN_SCHEMA

# ---------------- helpers ----------------

def truncate(text, limit=MAX_OUT):
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + "\n... [TRUNCATED] ...\n" + text[-half:]

def check_redirects(cmd):
    cwd = os.path.realpath(os.getcwd())
    for m in REDIRECT_RE.finditer(cmd):
        target = m.group(1).strip("\"'")
        if target in ("/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr") or target.startswith("&"):
            continue
        if not ARSENAL:
            if not re.fullmatch(r"[A-Za-z0-9_-]+\.txt", target):
                return False, "safe mode redirects may only write bare .txt report files in CWD (got: %s)" % target
            continue
        p = os.path.realpath(os.path.expanduser(target))
        if p == cwd or p.startswith(cwd + os.sep) or p == "/tmp" or p.startswith("/tmp" + os.sep):
            continue
        return False, "arsenal writes are restricted to CWD and /tmp (got: %s)" % target
    return True, "ok"

def _sudo_target(parts):
    """Return the binary sudo will run, skipping common sudo options."""
    rest = parts[1:]
    i = 0
    while i < len(rest):
        p = rest[i]
        if p in ("-u", "-g", "-p", "-C", "-U", "-r", "-t"):
            i += 2
            continue
        if p.startswith("-"):
            i += 1
            continue
        return os.path.basename(p.strip("\"'"))
    return None

def _shell_segments(cmd):
    """Split a shell command at unquoted ; && || | & operators and newlines."""
    segments = []
    for line in cmd.splitlines():
        try:
            lex = shlex.shlex(line, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            tokens = list(lex)
        except ValueError:
            return None
        current = []
        for tok in tokens:
            if tok in (";", "&&", "||", "|", "&", "|&", ";;"):
                if current:
                    segments.append(current)
                    current = []
            else:
                current.append(tok)
        if current:
            segments.append(current)
    return segments

def _segment_binary(tokens):
    """First real command word in a segment, skipping assignments/redirections."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in (">", ">>", "<", "<<", ">&", "<&", "&>", "&>>", "<<"):
            i += 2
            continue
        if re.fullmatch(r"\d+", tok):
            i += 1
            continue
        if "=" in tok and not tok.startswith("-"):
            i += 1
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return os.path.basename(tok.strip("\"'"))
    return None

def safety_check(cmd):
    c = cmd.strip()
    if not c:
        return False, "empty command"
    low = c.lower()

    for b in SHELL_ESCAPES:
        if b in low:
            return False, "blocked shell-exec pattern: " + b.strip()
    if not ARSENAL:
        for b in SAFE_BLOCKED:
            if b in low:
                return False, "blocked in safe mode: " + b.strip()

    segments = _shell_segments(c)
    if segments is None:
        return False, "unbalanced quotes in command"

    for tokens in segments:
        first = _segment_binary(tokens)
        if not first:
            continue

        if first in HOST_DESTRUCTIVE_CMDS:
            return False, "blocked host-destructive command: " + first
        if first == "sed" and any(t == "-i" or t.startswith("-i") for t in tokens):
            return False, "blocked in-place edit: sed -i"
        if first == "perl" and any(t == "-i" or t.startswith("-i") for t in tokens):
            return False, "blocked in-place edit: perl -i"

        if first == "sudo":
            target = _sudo_target(tokens)
            if not target:
                # read-only sudo introspection is allowed: sudo -n -l, sudo -V, etc.
                if tokens[1:] and all(t in ("-l", "-n", "-V", "-h", "--list",
                                            "--validate", "-v") for t in tokens[1:]):
                    continue
                return False, "sudo requires a target command"
            if target in HOST_DESTRUCTIVE_CMDS:
                return False, "blocked host-destructive command via sudo: " + target
            if not ARSENAL and target not in WHITELIST:
                return False, "safe mode: sudo target not whitelisted: " + target
            if ARSENAL and target not in ALL_SECURITY_TOOLS:
                return False, "sudo is only allowed for known security tools (got: %s)" % target
            if not shutil.which(target):
                return False, "tool not installed: " + target
            continue

        if ARSENAL:
            if first in ("bash", "sh", "zsh", "dash", "ksh", "csh", "fish"):
                return False, "generic shells are not allowed; propose a concrete security tool"
            if not shutil.which(first):
                return False, "binary not installed: " + first
        else:
            if first not in WHITELIST:
                return False, "binary not whitelisted: " + first

    for b in HOST_DESTRUCTIVE_PATTERNS:
        if b in low:
            return False, "blocked destructive pattern: " + b.strip()

    ok, why = check_redirects(c)
    if not ok:
        return False, why
    return True, "ok"

def _kill_process_group(proc, sig=signal.SIGTERM):
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except Exception:
        try:
            proc.send_signal(sig)
        except Exception:
            pass

def run_cmd(cmd, timeout=None, on_output=None, on_tick=None, cancel_event=None):
    """Run a shell command without blocking the UI silently.

    Output is captured to a temp file and polled, so callers can stream lines
    and show elapsed time. The child gets its own process group and is killed
    as a group on timeout or operator abort, preventing orphaned scans.
    """
    if timeout is None:
        timeout = CMD_TIMEOUT
    if cancel_event is not None and cancel_event.is_set():
        return "(command aborted before start)", -3
    t0 = time.time()
    fd, path = tempfile.mkstemp(prefix="nimrod_cmd_", suffix=".log", dir="/tmp")
    os.close(fd)
    proc = None
    reader = None
    captured = bytearray()
    timed_out = False
    try:
        with open(path, "wb") as outf:
            proc = subprocess.Popen(
                cmd, shell=True, stdin=subprocess.DEVNULL,
                stdout=outf, stderr=subprocess.STDOUT,
                start_new_session=True)
        _register_process(proc.pid)
        reader = open(path, "rb")
        last_tick = 0.0
        while True:
            chunk = reader.read()
            if chunk:
                if len(captured) < MAX_CAPTURE_BYTES:
                    captured.extend(chunk[:MAX_CAPTURE_BYTES - len(captured)])
                    if on_output:
                        for line in chunk[:131072].decode("utf-8", "replace").splitlines()[:200]:
                            if line.strip():
                                try:
                                    on_output(line)
                                except Exception:
                                    pass
            rc = proc.poll()
            if rc is not None:
                break
            if cancel_event is not None and cancel_event.is_set():
                _kill_process_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    _kill_process_group(proc, signal.SIGKILL)
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        pass
                return "(command aborted by operator)", -3
            elapsed = time.time() - t0
            if elapsed >= timeout:
                timed_out = True
                _kill_process_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    _kill_process_group(proc, signal.SIGKILL)
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        pass
                rc = -1
                break
            if on_tick and time.time() - last_tick >= 0.5:
                last_tick = time.time()
                try:
                    on_tick(elapsed, timeout)
                except Exception:
                    pass
            time.sleep(0.25)

        # drain anything written between the last poll and process exit
        if reader:
            try:
                chunk = reader.read()
                if chunk and len(captured) < MAX_CAPTURE_BYTES:
                    captured.extend(chunk[:MAX_CAPTURE_BYTES - len(captured)])
            except Exception:
                pass

        out = captured.decode("utf-8", "replace").strip() or "(no output)"
        if len(captured) >= MAX_CAPTURE_BYTES:
            out += "\n[output truncated at %d bytes]" % MAX_CAPTURE_BYTES
        if timed_out:
            out = "(command timed out after %ds)\n" % timeout + out
        return truncate(out), (rc if rc is not None else -1)
    except KeyboardInterrupt:
        if proc and proc.poll() is None:
            _kill_process_group(proc, signal.SIGINT)
            try:
                proc.wait(timeout=2)
            except Exception:
                _kill_process_group(proc, signal.SIGKILL)
        raise
    except Exception as e:
        if proc and proc.poll() is None:
            _kill_process_group(proc, signal.SIGKILL)
        return "(execution error: %s)" % e, -1
    finally:
        if proc and proc.poll() is None:
            _kill_process_group(proc, signal.SIGKILL)
        if proc:
            _unregister_process(proc.pid)
        if reader:
            try:
                reader.close()
            except Exception:
                pass
        try:
            os.unlink(path)
        except Exception:
            pass

def trim_context(history):
    total = sum(len(json.dumps(m, default=str)) for m in history)
    if total < MAX_CONTEXT_CHARS:
        return
    note = {"role": "system", "content": "[context compressed: earlier turns omitted]"}
    history[:] = [history[0], note] + history[-8:]

def make_system(mode):
    if ARSENAL:
        scope = SCOPE or "(operator must confirm authorization at plan approval)"
        return ("You are NIMROD, an authorized penetration-testing agent on the "
                "operator's Kali machine. Mode: " + MODES[mode] +
                " Propose terminal commands ONLY via the propose_command tool. "
                "You may use ANY installed security tool, including reconnaissance, "
                "web, exploitation, credential, wireless, Active Directory, and "
                "post-exploitation tools. Only operate inside the authorized scope: "
                + scope + ". Every command requires operator approval. Prefer "
                "non-interactive, non-destructive commands. Keep commands fast and bounded: "
                "commands time out after %ds, so prefer nmap -T4 -F/--top-ports, small "
                "wordlists, rate limits, and one-shot flags; avoid daemons and interactive "
                "tools. Never claim to have executed "
                "anything yourself. Be technical and concise. Arsenal: " % CMD_TIMEOUT
                + ", ".join(ALL_SECURITY_TOOLS))
    return ("You are NIMROD, a read-only security operations agent on the "
            "operator's Kali machine. Mode: " + MODES[mode] +
            " Propose terminal commands ONLY via the propose_command tool. "
            "Never claim to have executed anything yourself. All commands "
            "must be non-mutating except redirects to bare .txt report files. "
            "Be technical and concise. Whitelist: " + ", ".join(WHITELIST))

def stream_chat(messages):
    full = ""
    stream = client.chat.completions.create(model=MODEL, messages=messages, stream=True, **THINK_OPTS)
    for chunk in stream:
        delta = None
        try:
            delta = chunk.choices[0].delta.content
        except Exception:
            delta = None
        if delta:
            console.print(delta, end="")
            full += delta
    console.print()
    return full

def ask_analysis(cmd, out):
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": make_system(MODE)},
                {"role": "user", "content": "Command executed: %s\nOutput:\n%s\n\nAnalyze concisely: findings, anomalies, next recommended step." % (cmd, truncate(out, 4000))}
            ],
            timeout=min(API_TIMEOUT, 180), max_tokens=1024, **THINK_OPTS)
        return strip_thinking(resp.choices[0].message.content or "") or "(no analysis)"
    except Exception as e:
        return "(analysis unavailable - brain error: %s)" % explain_ai_error(e)

# ---------------- report writer ----------------

def build_report(plan, log, aborted=False, use_ai=True):
    ts = time.strftime("%Y%m%d_%H%M%S")
    fname = "nimrod_report_%s.txt" % ts
    narrative = "(narrative generation unavailable - raw log below)"
    if use_ai:
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": "You are NIMROD's report writer. Write a clear, concise penetration-test style mission report in plain text (no markdown): objectives, per-step what was done, what the results show, key findings, risk notes. Be brief."},
                    {"role": "user", "content": "MISSION SUMMARY: %s\n\nMISSION LOG:\n%s" % (str(plan.get("mission_summary", "")) if plan else "", json.dumps(log, indent=1)[:20000])}
                ],
                timeout=API_TIMEOUT, max_tokens=2048, **THINK_OPTS)
            narrative = strip_thinking(resp.choices[0].message.content or "") or narrative
        except Exception:
            pass
    lines = []
    lines.append("=" * 70)
    lines.append("NIMROD MISSION REPORT")
    lines.append("generated : " + time.ctime())
    lines.append("mode      : " + MODE)
    lines.append("arsenal   : " + ("ENABLED" if ARSENAL else "SAFE (read-only)"))
    lines.append("scope     : " + (SCOPE or "(not specified)"))
    lines.append("status    : " + ("ABORTED by operator (partial)" if aborted else "COMPLETED"))
    lines.append("=" * 70)
    lines.append("")
    lines.append("EXECUTIVE SUMMARY AND FINDINGS (AI-written)")
    lines.append("-" * 70)
    lines.append(narrative)
    lines.append("")
    lines.append("RAW TOOL EXECUTION LOG (verbatim outputs)")
    lines.append("-" * 70)
    for e in sorted(log, key=lambda x: int(x.get("step", 0))):
        lines.append("")
        lines.append("STEP %s: %s" % (e.get("step"), e.get("title")))
        lines.append("command : %s" % e.get("command"))
        lines.append("purpose : %s" % e.get("purpose"))
        lines.append("risk    : %s" % e.get("risk"))
        if e.get("depends_on"):
            lines.append("waited for : %s" % ", ".join(str(d) for d in e.get("depends_on")))
        if e.get("elapsed") is not None:
            lines.append("elapsed : %.1fs" % float(e.get("elapsed")))
        lines.append("rc      : %s" % e.get("rc"))
        lines.append("output  :")
        lines.append(e.get("output", ""))
        lines.append("AI analysis: %s" % e.get("analysis", ""))
    if not log:
        lines.append("(no steps executed)")
    try:
        with open(fname, "w") as f:
            f.write("\n".join(lines) + "\n")
        return fname
    except Exception as e:
        console.print("[red]report write failed: %s[/red]" % e)
        return None


# ---------------- phase 1: inventory ----------------

RECON_CMDS = [
    ("uname -a", "kernel"),
    ("hostname", "hostname"),
    ("head -3 /etc/os-release", "os"),
    ("id -un", "current user"),
    ("sudo -n true 2>/dev/null && echo passwordless-sudo || echo sudo-needs-password", "sudo status"),
    ("ip -brief addr 2>/dev/null || ifconfig -a 2>/dev/null | head -20", "interfaces"),
    ("ip route 2>/dev/null | head -5", "routes"),
    ("ip neigh 2>/dev/null | head -20", "neighbor cache (connected devices)"),
]

WORDLIST_CANDIDATES = [
    ("/usr/share/wordlists/dirb/common.txt", "web", "small web list - preferred for ffuf/gobuster/dirb"),
    ("/usr/share/wordlists/dirb/small.txt", "web", "small web list"),
    ("/usr/share/wfuzz/wordlist/general/common.txt", "web", "very small web list"),
    ("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt", "web", "medium web list - slower"),
    ("/usr/share/metasploit-framework/data/wordlists/unix_users.txt", "usernames", "small username list"),
    ("/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt", "passwords", "small password list - preferred"),
    ("/usr/share/nmap/nselib/data/passwords.lst", "passwords", "small password list"),
    ("/tmp/nimrod_wordlists/quick_users.txt", "usernames", "quick 20-user list - preferred"),
    ("/tmp/nimrod_wordlists/quick_passwords.txt", "passwords", "quick 1000-password list - preferred"),
    ("/tmp/nimrod_wordlists/rockyou_top10k.txt", "passwords", "10k passwords - only for a bounded, explicit brute-force step"),
    ("/usr/share/wordlists/rockyou.txt.gz", "passwords", "COMPRESSED - never pass this path to a tool"),
]

def _head_lines(src, dst, limit):
    if os.path.exists(dst):
        return
    try:
        with open(src, errors="ignore") as f, open(dst, "w") as o:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                o.write(line)
    except Exception:
        pass

def prepare_wordlists():
    """Create small, bounded wordlists under /tmp so the planner never has to
    hand a 14M-line rockyou list (or a missing .txt path) to a brute-force tool."""
    outdir = "/tmp/nimrod_wordlists"
    try:
        os.makedirs(outdir, exist_ok=True)
    except Exception:
        return
    top10k = os.path.join(outdir, "rockyou_top10k.txt")
    quickpw = os.path.join(outdir, "quick_passwords.txt")
    quickusr = os.path.join(outdir, "quick_users.txt")
    rockyou = "/usr/share/wordlists/rockyou.txt.gz"
    if not os.path.exists(top10k) and os.path.exists(rockyou):
        try:
            with gzip.open(rockyou, "rt", encoding="utf-8", errors="ignore") as f, open(top10k, "w") as o:
                for i, line in enumerate(f):
                    if i >= 10000:
                        break
                    o.write(line)
        except Exception:
            pass
    if not os.path.exists(quickpw):
        if os.path.exists(top10k):
            _head_lines(top10k, quickpw, 1000)
        else:
            _head_lines("/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt", quickpw, 1000)
    if not os.path.exists(quickusr):
        _head_lines("/usr/share/metasploit-framework/data/wordlists/unix_users.txt", quickusr, 20)

def discover_wordlists():
    """Return usable wordlists with line counts for the planner."""
    prepare_wordlists()
    found = []
    for path, kind, note in WORDLIST_CANDIDATES:
        if not os.path.isfile(path):
            continue
        if path.endswith(".gz"):
            lines = "compressed"
        else:
            try:
                with open(path, "rb") as f:
                    lines = sum(1 for _ in f)
            except Exception:
                lines = "?"
        found.append({"path": path, "kind": kind, "lines": lines, "note": note})
    return found

def discover_security_tools():
    """Return {category: [installed tool, ...]} for the local device."""
    groups = {}
    for group, names in SECURITY_TOOLS.items():
        installed = sorted({n for n in names.split() if shutil.which(n)})
        if installed:
            groups[group] = installed
    return groups

def auto_recon():
    console.print(Panel("[bold green]PHASE 1: PASSIVE SELF-INVENTORY (read-only)[/bold green]"))
    inv = {}
    for cmd, label in RECON_CMDS:
        out, rc = run_cmd(cmd, timeout=15)
        inv[label] = out
        console.print("[dim]$ %s[/dim]" % cmd)
        console.print(Panel(out, border_style="green", title=label))

    if ARSENAL:
        groups = discover_security_tools()
        found = sorted({t for tools in groups.values() for t in tools} |
                       {t for t in WHITELIST if shutil.which(t)})
        inv["arsenal_mode"] = "ENABLED (offensive/attack tools permitted)"
        if groups:
            tbl = Table(title="installed security arsenal (arsenal mode)", border_style="cyan")
            tbl.add_column("category", style="bold cyan", no_wrap=True)
            tbl.add_column("installed tools", style="green")
            for group, tools in groups.items():
                tbl.add_row(group, ", ".join(tools))
            console.print(tbl)
        else:
            console.print("[yellow]no catalogued security tools detected on PATH[/yellow]")
    else:
        found = [t for t in WHITELIST if shutil.which(t)]
        inv["arsenal_mode"] = "SAFE (read-only whitelist)"

    inv["available_tools"] = ", ".join(found) if found else "(none detected)"
    inv["authorized_scope"] = SCOPE or "(not specified)"
    inv["command_timeout_seconds"] = CMD_TIMEOUT
    if ARSENAL:
        inv["note"] = "Any other installed executable on PATH may also be used when named in the directive."
        wordlists = discover_wordlists()
        inv["wordlists"] = wordlists
        inv["performance_note"] = (
            "Keep every command well inside command_timeout_seconds. Prefer fast, bounded scans "
            "and the small wordlists marked preferred. Use large lists or full-port scans only when "
            "the directive explicitly asks for them."
        )
        if wordlists:
            console.print("[dim]%d usable wordlists indexed for the planner (small lists preferred).[/dim]"
                          % len(wordlists))
    if not ARSENAL:
        console.print(Panel(inv["available_tools"], title="available security tools (safe mode)", border_style="cyan"))
    else:
        console.print("[dim]%d tools are available to the planner; any other installed executable "
                      "may be used when named in the directive.[/dim]" % len(found))
    return inv

# ---------------- phase 2: plan engine ----------------

def strip_thinking(text):
    """Remove leaked chain-of-thought blocks emitted by reasoning models."""
    if not text:
        return ""
    # well-formed  thinking...<｜end▁of▁thinking｜> / <analysis>...</analysis> blocks
    text = re.sub(r"(?is)<(think|thinking|reasoning|analysis)>.*?</\1>\s*", "", text)
    # closing tag only (Qwen leaks "reasoning...\n</think>\n\nanswer" with no opener)
    text = re.sub(r"(?is)^.*?</(?:think|thinking|reasoning|analysis)>\s*", "", text)
    # leaked llama-style closing tag with no opener
    text = re.sub(r"(?is)^.*?<｜end▁of▁thinking｜>\s*", "", text)
    # markdown fences
    text = re.sub(r"^\s*```(?:json)?\s*", "", text, flags=re.I)
    text = re.sub(r"\s*```\s*$", "", text)
    return text.strip()

def parse_plan(text):
    """Extract the first valid plan JSON object from model output.

    Reasons models often emit reasoning with braces before the real JSON, so
    scan every '{' with a raw JSON decoder instead of regex-matching greedily.
    """
    clean = strip_thinking(text)
    decoder = json.JSONDecoder()
    for i, ch in enumerate(clean):
        if ch != "{":
            continue
        try:
            data, _ = decoder.raw_decode(clean[i:])
        except Exception:
            continue
        if isinstance(data, dict) and isinstance(data.get("steps"), list) and data["steps"]:
            return data
    return None

_OUTPUT_PATH_RE = re.compile(
    r'(?:^|\s)(?:-oN|-oX|-oG|-oA|-o|--output|-output|-of|-json-export|--json-export)\s+([^\s;|&]+)')
_WRITE_REDIRECT_RE = re.compile(r'>{1,2}\s*([^\s;|&]+)')

def _output_paths(cmd):
    paths = []
    for m in _OUTPUT_PATH_RE.finditer(cmd):
        val = m.group(1).strip("\"'")
        if not val or val == "-" or val.startswith("/dev/"):
            continue
        paths.append(val)
        if m.group(0).split()[0] == "-oA":
            paths.extend(val + ext for ext in (".nmap", ".xml", ".gnmap"))
    for m in _WRITE_REDIRECT_RE.finditer(cmd):
        val = m.group(1).strip("\"'")
        if val and not val.startswith("/dev/") and val != "-":
            paths.append(val)
    return paths

def _mentions_path(cmd, path):
    return re.search(r'(?<![\w-])' + re.escape(path) + r'(?![\w-])', cmd) is not None

def _plan_has_cycle(steps):
    deps = {int(s["step"]): set(s.get("depends_on") or []) for s in steps}
    visiting, done = set(), set()
    def visit(n):
        if n in done:
            return False
        if n in visiting:
            return True
        visiting.add(n)
        for d in deps.get(n, ()):
            if visit(d):
                return True
        visiting.remove(n)
        done.add(n)
        return False
    return any(visit(n) for n in deps)

def normalize_plan(plan):
    """Sanitize step numbers and dependency edges so the scheduler can trust them."""
    raw_steps = plan.get("steps") if isinstance(plan, dict) else None
    if not isinstance(raw_steps, list):
        return plan
    steps, used = [], set()
    for i, raw in enumerate(raw_steps, 1):
        if not isinstance(raw, dict):
            continue
        try:
            n = int(raw.get("step", i))
        except Exception:
            n = i
        while n in used:
            n += 1
        used.add(n)
        item = dict(raw)
        item["step"] = n
        item["command"] = str(item.get("command") or "").strip()
        item["title"] = str(item.get("title") or "step %d" % n)
        item["purpose"] = str(item.get("purpose") or "")
        item["risk"] = str(item.get("risk") or "medium")
        deps = item.get("depends_on", [])
        if isinstance(deps, (int, str)):
            deps = [deps]
        if not isinstance(deps, list):
            deps = []
        clean = []
        for d in deps:
            try:
                d = int(d)
            except Exception:
                continue
            if d != n and d not in clean:
                clean.append(d)
        item["depends_on"] = clean
        steps.append(item)
    valid = {s["step"] for s in steps}
    for s in steps:
        s["depends_on"] = [d for d in s.get("depends_on", []) if d in valid and d != s["step"]]
    # Heuristic: if a command reads a file written by another step, queue it
    # behind that producer even when the planner forgot depends_on. This is
    # two-pass so a producer listed later in the plan still blocks its reader.
    producers = {}
    for s in steps:
        for path in _output_paths(str(s.get("command", ""))):
            producers.setdefault(path, [])
            if s["step"] not in producers[path]:
                producers[path].append(s["step"])
    for s in steps:
        cmd = str(s.get("command", ""))
        for path, psteps in producers.items():
            if not _mentions_path(cmd, path):
                continue
            for p in psteps:
                if p != s["step"] and p not in s["depends_on"]:
                    s["depends_on"].append(p)
    if _plan_has_cycle(steps):
        console.print("[yellow]plan contained a dependency cycle; falling back to sequential order[/yellow]")
        for i, s in enumerate(steps):
            s["depends_on"] = [steps[i - 1]["step"]] if i else []
    out = dict(plan)
    out["steps"] = steps
    return out

def explain_ai_error(e):
    msg = str(e).splitlines()[0] if str(e) else e.__class__.__name__
    if len(msg) > 220:
        msg = msg[:220] + "..."
    # escape brackets so rich never parses error text as markup
    return msg.replace("[", "\\[").replace("]", "\\]")

def generate_plan(inv, directive):
    scope = SCOPE or str(inv.get("authorized_scope", "")).strip()
    if not scope or scope.startswith("(not specified"):
        scope = "(not specified - only act on the directive/inventory)"
    msgs = [
        {"role": "system", "content": plan_system() + " Mode: " + MODES[MODE] +
         " Do not output reasoning, analysis, or thinking text. Reply with the JSON object only."},
        {"role": "user", "content": "DIRECTIVE: " + directive +
         "\nAUTHORIZED SCOPE: " + scope +
         "\n\nINVENTORY:\n" + json.dumps(inv, indent=1)}
    ]
    for attempt in range(3):
        try:
            resp = client.chat.completions.create(
                model=MODEL, messages=msgs, timeout=API_TIMEOUT,
                max_tokens=4096, **THINK_OPTS)
        except Exception as e:
            console.print("[red]brain unreachable while building plan (%s)[/red]" % explain_ai_error(e))
            if attempt < 2:
                wait = 3 * (attempt + 1)
                console.print("[yellow]retrying in %ds (%d/3)...[/yellow]" % (wait, attempt + 1))
                time.sleep(wait)
                continue
            console.print("[yellow]check that the LiteLLM proxy + ngrok tunnel + remote Ollama session are alive.[/yellow]")
            return None
        text = resp.choices[0].message.content or ""
        plan = parse_plan(text)
        if plan:
            return normalize_plan(plan)
        console.print("[yellow]plan attempt %d produced no valid JSON (got %d chars); retrying...[/yellow]"
                      % (attempt + 1, len(text)))
        msgs.append({"role": "assistant", "content": text or "(empty)"})
        msgs.append({"role": "user", "content": "Invalid output. Respond with ONLY the JSON object, no thinking, no fences."})
    console.print("[yellow]brain returned unparseable plan JSON three times; giving up on auto-plan.[/yellow]")
    return None

# ---------------- approval menu (chat / manual mode) ----------------

def approve_menu(cmd, title, purpose, risk):
    console.print(Panel(Syntax(cmd, "bash"),
                        title="[bold yellow]PROPOSED: %s[/bold yellow]" % title,
                        border_style="yellow"))
    console.print("purpose : " + purpose)
    console.print("risk    : " + risk)
    while True:
        try:
            ch = console.input("[bold cyan]decision[/bold cyan] \\[a]pprove \\[d]eny \\[e]dit \\[s]kip \\[x]abort > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "d", cmd
        if ch in ("a", "approve", "y", "yes"):
            return "a", cmd
        if ch in ("d", "deny", "n", "no"):
            return "d", cmd
        if ch == "s":
            return "s", cmd
        if ch == "x":
            return "x", cmd
        if ch == "e":
            new = console.input("[bold cyan]edited command[/bold cyan] > ").strip()
            if new:
                ok, why = safety_check(new)
                if ok:
                    cmd = new
                    console.print("[green]safety check passed[/green]")
                else:
                    console.print("[red]safety FAILED: %s[/red]" % why)
            continue
        console.print("[dim]invalid choice[/dim]")


# ---------------- phase 3: AUTO-PILOT mission + report ----------------

def run_mission(plan, history):
    global MISSION_LOG, LAST_PLAN, LAST_ABORTED
    plan = normalize_plan(plan)
    MISSION_LOG = []
    LAST_PLAN = plan
    LAST_ABORTED = False
    steps = plan.get("steps") or []
    if not steps:
        console.print("[red]mission plan has no steps[/red]")
        return
    jobs = 1 if SEQUENTIAL else max(1, min(8, MAX_JOBS))

    console.print(Panel(str(plan.get("mission_summary", "")), title="MISSION SUMMARY", border_style="magenta"))
    if ARSENAL:
        execution = ("[bold]one tool at a time[/bold] (--sequential)" if jobs == 1
                     else "up to [bold]%d independent tools in parallel[/bold]" % jobs)
        console.print(Panel("[bold red]ARSENAL MODE[/bold red] - these commands can be offensive.\n"
                            "Only run them against systems you own or have written authorization to test.\n"
                            "[bold]Authorized scope:[/bold] " + (SCOPE or "(not specified - confirm before approving)") +
                            "\nExecution: " + execution + "; dependent steps wait in the queue.\n"
                            "Every command below is visible for your review; Ctrl+C is the kill switch.",
                            title="AUTHORIZATION CHECK", border_style="red"))
    tbl = Table(title="MISSION PLAN (full plan - read before approving)")
    tbl.add_column("#", style="bold")
    tbl.add_column("step")
    tbl.add_column("command", style="green")
    tbl.add_column("purpose")
    tbl.add_column("waits for", style="cyan")
    tbl.add_column("risk", style="red")
    for s in steps:
        deps_txt = ", ".join(str(d) for d in s.get("depends_on", [])) or "-"
        tbl.add_row(str(s.get("step")), escape(str(s.get("title"))), escape(str(s.get("command"))),
                    escape(str(s.get("purpose"))), deps_txt, str(s.get("risk")))
    console.print(tbl)

    jobs_label = "sequential" if jobs == 1 else "max %d parallel" % jobs
    try:
        ch = console.input("[bold yellow]APPROVE ENTIRE PLAN?[/bold yellow] \\[a]uto-run all (%s) / \\[d]eny > " % jobs_label).strip().lower()
    except (EOFError, KeyboardInterrupt):
        ch = "d"
    if ch not in ("a", "approve", "y", "yes"):
        console.print("[red]plan not approved. mission cancelled.[/red]")
        return

    by_num = {int(s["step"]): s for s in steps}
    deps = {n: [int(d) for d in s.get("depends_on", [])] for n, s in by_num.items()}

    blocked = {}
    for n, s in by_num.items():
        cmd = str(s.get("command", "")).strip()
        ok, why = safety_check(cmd)
        if not cmd:
            blocked[n] = "empty command"
        elif not ok:
            blocked[n] = why

    pending = set(by_num)
    running = {}
    completed = set()
    failed = set()
    skipped = {}
    results_lines = []
    analysis_lines = []
    analysis_pending = set()
    analysis_slots = {}
    log_by_step = {}
    abort_event = threading.Event()
    analysis_stop = threading.Event()
    q = queue.Queue()
    analysis_q = queue.Queue()
    last_ui = [0.0]
    executor = ThreadPoolExecutor(max_workers=jobs)

    def worker(n, s):
        cmd = str(s.get("command", "")).strip()
        last_out = [0.0]

        def on_output(line):
            now = time.time()
            if now - last_out[0] >= 0.1:
                q.put(("out", n, line[:400]))
                last_out[0] = now

        t0 = time.time()
        try:
            out, rc = run_cmd(cmd, on_output=on_output, cancel_event=abort_event)
        except Exception as e:
            out, rc = "(execution error: %s)" % e, -1
        q.put(("done", n, rc, out, time.time() - t0))

    def analysis_worker():
        while not analysis_stop.is_set():
            try:
                item = analysis_q.get(timeout=0.25)
            except queue.Empty:
                continue
            if item is None:
                break
            n, cmd, out = item
            try:
                text = ask_analysis(cmd, out)
            except Exception as e:
                text = "(analysis unavailable: %s)" % e
            q.put(("analysis", n, text))

    analysis_thread = threading.Thread(target=analysis_worker, name="nimrod-analysis", daemon=True)
    analysis_thread.start()

    def record_skip(n, reason):
        if n in skipped or n in completed or n in running:
            return
        skipped[n] = reason
        pending.discard(n)
        s = by_num[n]
        title = str(s.get("title", "step"))
        cmd = str(s.get("command", "")).strip()
        results_lines.extend([
            "",
            "[bold yellow]== STEP %d: %s [SKIPPED][/bold yellow]" % (n, escape(title)),
            "reason: " + escape(reason),
            "$ " + escape(cmd),
            "waited for: " + (", ".join(str(d) for d in deps[n]) or "-"),
        ])
        MISSION_LOG.append({
            "step": n, "title": title, "command": cmd,
            "purpose": str(s.get("purpose", "")), "risk": str(s.get("risk", "medium")),
            "rc": -2, "output": "SKIPPED: " + reason,
            "analysis": "(step not run)", "elapsed": 0, "depends_on": deps[n],
        })

    def propagate_skips():
        changed = True
        while changed:
            changed = False
            for n in sorted(pending):
                if n in blocked:
                    record_skip(n, "safety: " + blocked[n])
                    changed = True
                    continue
                bad = next((d for d in deps[n] if d in failed or d in skipped or d in blocked), None)
                if bad is not None:
                    record_skip(n, "dependency step %d failed or was skipped" % bad)
                    changed = True

    def start_ready():
        while len(running) < jobs:
            started = False
            for n in sorted(pending):
                if n in blocked:
                    continue
                if any(d not in completed for d in deps[n]):
                    continue
                if any(d in failed or d in skipped or d in blocked for d in deps[n]):
                    continue
                pending.discard(n)
                s = by_num[n]
                running[n] = {
                    "title": str(s.get("title", "step")),
                    "command": str(s.get("command", "")).strip(),
                    "deps": deps[n],
                    "start": time.time(),
                    "lines": [],
                }
                executor.submit(worker, n, s)
                started = True
                break
            if not started:
                break

    def running_text():
        if not running:
            if analysis_pending:
                return "(no active tools; %d AI analysis task(s) queued)" % len(analysis_pending)
            return "(no active tools; %d queued)" % len(pending)
        lines = []
        for n in sorted(running):
            info = running[n]
            elapsed = int(time.time() - info["start"])
            lines.append("STEP %d  %s  [%ds/%ds]" %
                         (n, escape(info["title"][:38]), elapsed, CMD_TIMEOUT))
            last = info["lines"][-1] if info["lines"] else "(starting...)"
            lines.append("  " + escape(last[:140]))
        return "\n".join(lines)

    def render():
        layout = Layout()
        size = min(14, max(5, 2 + 2 * len(running))) if running else 4
        layout.split_column(Layout(name="running", size=size), Layout(name="body"))
        layout["body"].split_row(Layout(name="results", ratio=3), Layout(name="brain", ratio=2))
        layout["running"].update(Panel(running_text(),
                                       title="RUNNING (max %d, timeout %ds)" % (jobs, CMD_TIMEOUT),
                                       border_style="green"))
        layout["results"].update(Panel("\n".join(results_lines[-80:]) or "(waiting for results)",
                                       title="RESULTS (completion order / popped)", border_style="green"))
        layout["brain"].update(Panel("\n".join(analysis_lines[-80:]) or "(waiting for analysis)",
                                     title="ANALYSIS (brain)", border_style="cyan"))
        return layout

    def append_result(n, info, rc, out, elapsed):
        results_lines.extend([
            "",
            "[bold]== STEP %d: %s [rc=%d, %.1fs][/bold]" % (n, escape(info["title"]), rc, elapsed),
            "$ " + escape(info["command"]),
        ])
        if info["deps"]:
            results_lines.append("waited for: " + ", ".join(str(d) for d in info["deps"]))
        results_lines.append(escape(truncate(out, 1500)))

    def append_analysis_placeholder(n, info):
        analysis_lines.extend([
            "",
            "[bold cyan]== STEP %d: %s[/bold cyan]" % (n, escape(info["title"])),
            "[AI analyzing...]",
        ])
        return len(analysis_lines) - 1

    aborted = False
    try:
        with Live(render(), refresh_per_second=4, console=console) as live:
            def update_ui(force=False):
                now = time.time()
                if force or now - last_ui[0] >= 0.25:
                    live.update(render())
                    last_ui[0] = now

            propagate_skips()
            start_ready()
            update_ui(force=True)

            while pending or running or analysis_pending:
                try:
                    ev = q.get(timeout=0.25)
                except queue.Empty:
                    update_ui()
                    if not running and pending:
                        propagate_skips()
                        start_ready()
                        if not running and pending:
                            for n in list(pending):
                                record_skip(n, "unresolved dependency")
                            update_ui(force=True)
                    continue
                kind = ev[0]
                if kind == "out":
                    n, line = ev[1], ev[2]
                    info = running.get(n)
                    if info:
                        info["lines"].append(line)
                        if len(info["lines"]) > 200:
                            del info["lines"][:100]
                        update_ui()
                elif kind == "done":
                    n, rc, out, elapsed = ev[1], ev[2], ev[3], ev[4]
                    info = running.pop(n, None)
                    if info is None:
                        continue
                    completed.add(n)
                    if (out.startswith("(command timed out") or out.startswith("(command aborted")
                            or out.startswith("(execution error")):
                        failed.add(n)
                    live.console.print("[bold green]RESULT POPPED[/bold green] step %d: %s [rc=%d, %.1fs]" %
                                       (n, escape(info["title"]), rc, elapsed))
                    live.console.print(escape(truncate(out, 900)))
                    append_result(n, info, rc, out, elapsed)
                    analysis_idx = append_analysis_placeholder(n, info)
                    update_ui(force=True)
                    propagate_skips()
                    start_ready()
                    entry = {
                        "step": n, "title": info["title"], "command": info["command"],
                        "purpose": str(by_num[n].get("purpose", "")),
                        "risk": str(by_num[n].get("risk", "medium")),
                        "rc": rc, "output": truncate(out, 20000),
                        "analysis": "(analysis queued)", "elapsed": round(elapsed, 2),
                        "depends_on": info["deps"],
                    }
                    MISSION_LOG.append(entry)
                    log_by_step[n] = entry
                    analysis_slots[n] = analysis_idx
                    analysis_pending.add(n)
                    analysis_q.put((n, info["command"], out))
                    update_ui(force=True)
                elif kind == "analysis":
                    n, text = ev[1], ev[2]
                    analysis_pending.discard(n)
                    idx = analysis_slots.pop(n, None)
                    if idx is not None and 0 <= idx < len(analysis_lines):
                        analysis_lines[idx] = escape(truncate(text, 1200))
                    entry = log_by_step.get(n)
                    if entry:
                        entry["analysis"] = text
                    live.console.print("[bold cyan]AI step %d:[/bold cyan] %s" %
                                       (n, escape(truncate(text, 700))))
                    history.append({"role": "assistant", "content": "[step %s] %s -> %s" %
                                    (n, by_num[n].get("command", ""), str(text)[:800])})
                    update_ui(force=True)
            results_lines.extend(["", "[bold green][MISSION COMPLETE][/bold green]"])
            update_ui(force=True)
    except KeyboardInterrupt:
        aborted = True
        abort_event.set()
        console.print("\n[red]KILL SWITCH: mission aborted by operator.[/red]")
        executor.shutdown(wait=True, cancel_futures=True)
        for n, info in list(running.items()):
            entry = log_by_step.get(n)
            if entry is None:
                entry = {
                    "step": n, "title": info["title"], "command": info["command"],
                    "purpose": str(by_num[n].get("purpose", "")),
                    "risk": str(by_num[n].get("risk", "medium")),
                    "rc": -3, "output": "(mission aborted by operator)",
                    "analysis": "(mission aborted)", "elapsed": round(time.time() - info["start"], 2),
                    "depends_on": info["deps"],
                }
                MISSION_LOG.append(entry)
            else:
                entry["rc"] = -3
                entry["output"] = "(mission aborted by operator)"
                entry["analysis"] = "(mission aborted)"
        history.append({"role": "assistant", "content": "[mission aborted by operator]"})
    finally:
        if not aborted:
            executor.shutdown(wait=True)
        analysis_stop.set()
        try:
            analysis_q.put_nowait(None)
        except Exception:
            pass
        if not aborted:
            analysis_thread.join(timeout=5)

    LAST_ABORTED = aborted
    with console.status("[bold magenta]NIMROD is writing the mission report...[/bold magenta]", spinner="dots"):
        fname = build_report(plan, MISSION_LOG, aborted=aborted, use_ai=not aborted)
    if fname:
        console.print(Panel("[bold green]MISSION REPORT SAVED:[/bold green] ./" + fname, border_style="green"))



# ---------------- phase 4: interactive chat + tools ----------------

def chat_turn(history, user_text):
    history.append({"role": "user", "content": user_text})
    for _ in range(6):
        trim_context(history)
        try:
            with console.status("[bold magenta]NIMROD is thinking...[/bold magenta]", spinner="dots"):
                resp = client.chat.completions.create(model=MODEL, messages=history, tools=TOOLS, tool_choice="auto", timeout=API_TIMEOUT, **THINK_OPTS)
        except Exception as e:
            console.print(Panel("[red]brain unreachable:[/red] " + explain_ai_error(e) +
                                "\n[yellow]check the LiteLLM proxy, ngrok tunnel, and remote Ollama session,[/yellow]"
                                "\n[yellow]then retry (run `nimrod --ping` or `nimrod --engine-waker`).[/yellow]",
                                title="NIMROD OFFLINE", border_style="red"))
            return
        msg = resp.choices[0].message
        content = msg.content or ""
        if content:
            console.print(Panel(Markdown(content), title="NIMROD", border_style="magenta"))
        if not msg.tool_calls:
            history.append({"role": "assistant", "content": content})
            return
        calls = []
        for tc in msg.tool_calls:
            calls.append({"id": tc.id, "type": "function",
                          "function": {"name": tc.function.name, "arguments": tc.function.arguments}})
        history.append({"role": "assistant", "content": content or None, "tool_calls": calls})
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments or "{}")
            cmd = str(args.get("command", ""))
            reason = str(args.get("reason", ""))
            ok, why = safety_check(cmd)
            if not ok:
                result = "BLOCKED by safety layer: " + why
                console.print("[red]BLOCKED: %s[/red]" % why)
            else:
                decision, cmd2 = approve_menu(cmd, "agent request", reason, "agent-requested")
                if decision == "a":
                    with console.status("[bold green]running command...[/bold green]", spinner="dots") as st:
                        def tick(elapsed, total):
                            st.update("[bold green]running %ds / %ds...[/bold green]" % (elapsed, total))
                        out, rc = run_cmd(cmd2, on_tick=tick)
                    console.print(Panel(out, title="output | rc=%d" % rc, border_style="green"))
                    result = out
                elif decision == "s":
                    result = "Operator skipped this command."
                elif decision == "x":
                    result = "Operator aborted. Stop proposing commands and summarize now."
                else:
                    result = "Operator denied this command."
            history.append({"role": "tool", "tool_call_id": tc.id, "content": truncate(result)})
    console.print("[dim](tool loop limit reached)[/dim]")

def interactive(history):
    global ARSENAL, SCOPE, LAST_INV
    help_text = ("chat | /help /tools /devices /report /plan <dir> /arsenal /safe "
                 "/scope <targets> /clear /exit (or exit/q) | !<cmd> manual run")
    console.print(Panel(help_text, title="INTERACTIVE MODE", border_style="cyan"))
    while True:
        try:
            text = console.input("[bold cyan]nimrod> [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        if text in ("/exit", "/quit", "exit", "quit", "q"):
            break
        if text == "/help":
            console.print(Panel(help_text, title="help"))
            continue
        if text == "/tools":
            if ARSENAL:
                groups = discover_security_tools()
                tbl = Table(title="installed security arsenal", border_style="cyan")
                tbl.add_column("category", style="bold cyan", no_wrap=True)
                tbl.add_column("installed tools", style="green")
                for group, tools in groups.items():
                    tbl.add_row(group, ", ".join(tools))
                console.print(tbl)
            else:
                console.print(Panel(", ".join(WHITELIST), title="safe-mode whitelist"))
            continue
        if text == "/arsenal":
            ARSENAL = True
            history[0] = {"role": "system", "content": make_system(MODE)}
            LAST_INV = auto_recon()
            console.print("[bold red]arsenal mode enabled[/bold red] - any installed security tool is allowed")
            continue
        if text == "/safe":
            ARSENAL = False
            history[0] = {"role": "system", "content": make_system(MODE)}
            LAST_INV = auto_recon()
            console.print("[bold green]safe mode enabled[/bold green] - read-only whitelist only")
            continue
        if text.startswith("/scope "):
            SCOPE = text[7:].strip()
            LAST_INV["authorized_scope"] = SCOPE or "(not specified)"
            history[0] = {"role": "system", "content": make_system(MODE)}
            console.print("[cyan]authorized scope set:[/cyan] " + (SCOPE or "(cleared)"))
            continue
        if text == "/report":
            if MISSION_LOG:
                with console.status("[bold magenta]NIMROD is writing the mission report...[/bold magenta]", spinner="dots"):
                    fname = build_report(LAST_PLAN, MISSION_LOG, aborted=LAST_ABORTED)
                if fname:
                    console.print(Panel("[bold green]REPORT SAVED:[/bold green] ./" + fname, border_style="green"))
            else:
                console.print("[yellow]no mission log yet - run /plan first[/yellow]")
            continue
        if text == "/clear":
            history[:] = [history[0]]
            console.print("[yellow]context cleared[/yellow]")
            continue
        if text == "/devices":
            out, rc = run_cmd("ip neigh 2>/dev/null; arp -a 2>/dev/null | head -20", timeout=15)
            console.print(Panel(out, title="known connected devices"))
            continue
        if text.startswith("/plan "):
            plan = generate_plan(LAST_INV, text[6:])
            if plan:
                run_mission(plan, history)
            else:
                console.print("[red]plan engine returned unparsable output[/red]")
            continue
        if text.startswith("!"):
            cmd = text[1:].strip()
            ok, why = safety_check(cmd)
            if not ok:
                console.print("[red]blocked: %s[/red]" % why)
                continue
            decision, cmd = approve_menu(cmd, "manual run", "operator-initiated", "manual")
            if decision == "a":
                with console.status("[bold green]running command...[/bold green]", spinner="dots") as st:
                    def tick(elapsed, total):
                        st.update("[bold green]running %ds / %ds...[/bold green]" % (elapsed, total))
                    out, rc = run_cmd(cmd, on_tick=tick)
                console.print(Panel(out, title="rc=%d" % rc, border_style="green"))
            continue
        chat_turn(history, text)

# ---------------- diagnostics ----------------

def _default_ngrok_url():
    """Prefer the API base currently configured in litellm so diagnostics don't
    point at a stale tunnel URL after a Kaggle restart."""
    cfg = os.path.expanduser(os.environ.get("NIMROD_LITELLM_CONFIG", "~/nimrod_config.yaml"))
    try:
        with open(cfg) as f:
            m = re.search(r'api_base:\s*"?([^"\s]+)"?', f.read())
        if m and m.group(1).startswith("http"):
            return m.group(1).rstrip("/")
    except Exception:
        pass
    return "https://revision-culpable-lilly.ngrok-free.dev"

NGROK_URL = (os.environ.get("NIMROD_NGROK_URL") or _default_ngrok_url()).rstrip("/")

def _http_probe(url, timeout=20):
    """Return (ok, status, secs, detail) for a HEAD/GET probe without the openai lib."""
    import urllib.request
    import urllib.error
    t0 = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "nimrod-ping"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200).decode("utf-8", "replace")
            return True, r.status, time.time() - t0, body
    except urllib.error.HTTPError as e:
        return False, e.code, time.time() - t0, str(e)
    except Exception as e:
        return False, 0, time.time() - t0, "%s: %s" % (e.__class__.__name__, explain_ai_error(e))

_KEEPALIVE_STOP = threading.Event()

def _ollama_json(path, payload=None, timeout=15):
    import urllib.request
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"User-Agent": "nimrod-keepalive"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(NGROK_URL + path, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(8192).decode("utf-8", "replace"))

def _remote_ollama_model():
    global KEEPALIVE_REMOTE_MODEL
    if KEEPALIVE_REMOTE_MODEL:
        return KEEPALIVE_REMOTE_MODEL
    try:
        data = _ollama_json("/api/ps", timeout=10)
        models = data.get("models") or []
        if models:
            KEEPALIVE_REMOTE_MODEL = models[0].get("name") or models[0].get("model")
            return KEEPALIVE_REMOTE_MODEL
    except Exception:
        pass
    try:
        data = _ollama_json("/api/tags", timeout=10)
        models = data.get("models") or []
        if models:
            KEEPALIVE_REMOTE_MODEL = models[0].get("name") or models[0].get("model")
    except Exception:
        pass
    return KEEPALIVE_REMOTE_MODEL

def keepalive_once():
    """Refresh the remote Ollama keep-alive without generating tokens."""
    global KEEPALIVE_REMOTE_MODEL
    model = _remote_ollama_model()
    if not model:
        return False
    try:
        _ollama_json("/api/generate",
                     {"model": model, "prompt": "", "keep_alive": "10m", "stream": False},
                     timeout=30)
        return True
    except Exception:
        KEEPALIVE_REMOTE_MODEL = None
        return False

def keepalive_loop():
    while not _KEEPALIVE_STOP.wait(KEEPALIVE_INTERVAL):
        keepalive_once()

def start_keepalive():
    if os.environ.get("NIMROD_KEEPALIVE", "1").lower() in ("0", "false", "no", "off"):
        return
    if not NGROK_URL:
        return
    threading.Thread(target=keepalive_loop, name="nimrod-keepalive", daemon=True).start()
    console.print("[dim]keep-alive on: remote model stays loaded during long scans "
                  "(NIMROD_KEEPALIVE=0 disables).[/dim]")

def warmup_engine():
    """Fire a 1-token request so the remote model loads into GPU before Phase 2 needs it."""
    t0 = time.time()
    console.print("[dim]warming up engine (loading remote model into GPU; first time after idle can take minutes)...[/dim]")
    try:
        client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": "Reply with exactly one word."}],
            max_tokens=1,
            timeout=API_TIMEOUT, **THINK_OPTS)
        console.print("[green]engine warm:[/green] %s ready in %.1fs - model is resident, Phase 2 will be fast" %
                      (MODEL, time.time() - t0))
    except Exception as e:
        console.print("[yellow]warmup failed: %s (plan request will retry lazily)[/yellow]"
                      % explain_ai_error(e))

def wake_engine():
    """Standalone engine waker: verify chain, force the remote model to load,
    and PRINT THE MODEL'S ACTUAL REPLY as proof the brain is awake."""
    banner()
    console.print(Panel("[bold cyan]NIMROD --engine-waker : force brain awake + proof of life[/bold cyan]"))
    ok1, s1, t1, d1 = _http_probe(API_BASE.replace("/v1", "") + "/v1/models", timeout=10)
    if ok1:
        st1 = "[green]OK[/green] " + "HTTP %s in %.2fs" % (s1, t1)
    else:
        st1 = "[red]FAIL[/red] " + d1
    console.print("[bold]hop 1[/bold]  local LiteLLM proxy   " + st1)
    if not ok1:
        console.print("[red]dead at hop 1 - is litellm running on port 4001?[/red]")
        return 1
    ok2, s2, t2, d2 = _http_probe(NGROK_URL + "/api/tags", timeout=20)
    if ok2:
        st2 = "[green]OK[/green] " + "HTTP %s in %.2fs" % (s2, t2)
    else:
        st2 = "[red]FAIL[/red] " + d2
    console.print("[bold]hop 2[/bold]  ngrok tunnel            " + st2)
    if not ok2:
        console.print("[red]dead at hop 2 - is the ngrok process alive on Kaggle?[/red]")
        return 1
    console.print("[bold]hop 3[/bold]  remote Ollama (Kaggle) - firing wake request...")
    console.print("[dim]if Kaggle evicted the ~18GB model, this wait = model reload, can take minutes[/dim]")
    t0 = time.time()
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are NIMROD, a tactical AI security agent. "
                                              "Answer directly in one short line. Never output internal "
                                              "reasoning or thinking blocks."},
                {"role": "user", "content": "Say your name, confirm you are awake and receiving my orders. One short line."}
            ],
            max_tokens=1024,
            timeout=API_TIMEOUT, **THINK_OPTS)
        dt = time.time() - t0
        text = (resp.choices[0].message.content or "(empty reply)").strip()
        # strip leaked chain-of-thought if the model still thinks
        text = strip_thinking(text) or "(empty reply - model spent all tokens thinking)"
        console.print(Panel("[green bold]ENGINE AWAKE - here is what the brain said:[/green bold]\n"
                            "[white]\"%s\"[/white]" % text,
                            subtitle="model=%s | woke in %.1fs (includes model load if it was evicted)"
                                     % (MODEL, dt),
                            border_style="green"))
    except Exception as e:
        console.print("[red]engine failed to wake:[/red] " + explain_ai_error(e))
        return 1
    t1 = time.time()
    try:
        client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": "Reply with exactly one word."}],
            max_tokens=1,
            timeout=API_TIMEOUT, **THINK_OPTS)
        console.print("[green]warm check:[/green] follow-up request finished in %.1fs - engine is HOT, "
                      "Phase 2 will now use this speed (run NIMROD right away)"
                      % (time.time() - t1))
    except Exception as e:
        console.print("[yellow]wake succeeded but warm check failed:[/yellow] " + explain_ai_error(e))
    return 0

def ping_chain():
    """Test the full request path: local LiteLLM proxy -> ngrok -> remote Ollama on Kaggle."""
    console.print(Panel("[bold cyan]NIMROD --ping : full chain diagnostic[/bold cyan]"))
    ok1, s1, t1, d1 = _http_probe(API_BASE.replace("/v1", "") + "/v1/models", timeout=10)
    console.print("[bold]hop 1[/bold]  local LiteLLM proxy  %s  %s" %
                  ("[green]OK[/green]" if ok1 else "[red]FAIL[/red]",
                   "HTTP %s in %.2fs" % (s1, t1) if s1 else d1))
    if not ok1:
        console.print("[red]chain dead at hop 1 - check: litellm --config <cfg> --port 4001 is running[/red]")
        return 1
    ok2, s2, t2, d2 = _http_probe(NGROK_URL + "/api/tags", timeout=20)
    console.print("[bold]hop 2[/bold]  ngrok tunnel             %s  %s" %
                  ("[green]OK[/green]" if ok2 else "[red]FAIL[/red]",
                   "HTTP %s in %.2fs" % (s2, t2) if s2 else d2))
    if not ok2:
        console.print("[red]chain dead at hop 2 - check: ngrok process alive on Kaggle + tunnel not timed out[/red]")
        return 1
    ok3, s3, t3, d3 = _http_probe(NGROK_URL + "/api/ps", timeout=20)
    loaded = False
    detail = d3
    if ok3:
        try:
            data = json.loads(d3)
            for m in data.get("models", []):
                console.print("[bold]hop 3[/bold]  remote Ollama (Kaggle)   [green]OK[/green]  HTTP %s in %.2fs - model LOADED: %s" %
                              (s3, t3, m.get("name")))
                loaded = True
        except Exception:
            detail = d3[:200]
    if ok3 and not loaded:
        console.print("[bold]hop 3[/bold]  remote Ollama (Kaggle)   [green]OK[/green]  HTTP %s in %.2fs - NO MODEL LOADED (first request will load ~18GB, takes minutes)" % (s3, t3))
    elif not ok3:
        console.print("[bold]hop 3[/bold]  remote Ollama (Kaggle)   [red]FAIL[/red]  %s" % (detail[:160] if detail else d3))
        return 1
    console.print("[dim]tip: to see each request land on Kaggle, watch the Ollama process console there "
                  "(each /api/chat + /api/generate prints an INFO line with request duration and count).[/dim]")
    return 0

# ---------------- boot ----------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="nimrod",
        description="NIMROD v1.2 - authorized security testing agent with safe recon and arsenal modes "
                    "(plan approval | auto-pilot | auto reports).",
        epilog="Flags are optional; with no flags NIMROD starts in arsenal mode and drops into "
               "interactive mode, asking for mode + directive at the prompts.",
    )
    p.add_argument("-m", "--mode", choices=["red", "blue", "purple"],
                   help="operational mode (skips the interactive mode prompt). default: purple")
    p.add_argument("-d", "--directive", metavar="TEXT",
                   help="mission directive to plan+run at startup (skips the directive prompt)")
    p.add_argument("--no-auto", action="store_true",
                   help="skip the startup directive/plan even if --directive is given (chat only)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--arsenal", action="store_true",
                   help="allow any installed security/attack tool (default)")
    g.add_argument("--safe", action="store_true",
                   help="read-only mode: restrict commands to the safe recon whitelist")
    p.add_argument("-s", "--scope", metavar="TEXT",
                   help="authorized target scope (hosts/CIDRs/domains) given to the planner")
    p.add_argument("-t", "--timeout", type=int, metavar="SECONDS",
                   help="per-command timeout in seconds (overrides NIMROD_TIMEOUT)")
    p.add_argument("-j", "--jobs", type=int, metavar="N",
                   help="max independent tools to run in parallel (default: NIMROD_JOBS or 4, capped at 8)")
    p.add_argument("--sequential", action="store_true",
                   help="run mission steps one at a time (disables the parallel scheduler)")
    p.add_argument("--model", metavar="NAME", help="LLM model name (overrides NIMROD_MODEL)")
    p.add_argument("-b", "--api-base", metavar="URL", help="API base URL (overrides NIMROD_API_BASE)")
    p.add_argument("--ping", action="store_true",
                   help="diagnostic: test proxy + full chain (proxy -> ngrok -> remote Ollama), then exit")
    p.add_argument("-e", "--engine-waker", "--engine_waker", dest="engine_waker",
                   action="store_true",
                   help="wake the remote brain now: force model load, print its actual reply as proof, then exit")
    p.add_argument("-v", "--version", action="version", version="NIMROD v1.2")
    return p.parse_args(argv)

def banner():
    art = r'''
█████▄▄▄▄    ▄█    ▄▄▄▄█████▄▄▄▄     ▄████████  ▄██████▄  ██████████▄  
█████▀▀▀███ ███  ▄██▀▀▀███▀▀▀███   ███     ███ ███    ███ ███   ▀████ 
███     ███ ███▌ ███   ███   ███   ███     ███ ███    ███ ███     ███ 
███     ███ ███▌ ███   ███   ███  ▄████▄▄▄▄██▀ ███    ███ ███     ███ 
███     ███ ███▌ ███   ███   ███  ▀▀███▀▀▀▀▀   ███    ███ ███     ███ 
███     ███ ███  ███   ███   ███ ▀████████████ ███    ███ ███     ███ 
███     ███ ███  ███   ███   ███   ███     ███ ███    ███ ███   ▄████ 
 ▀█     █▀  █▀    ▀█   ███   █▀    ███     ███  ▀██████▀  ██████████▀  
                                   ███     ███                        
    '''
    subtitle = ("authorized pentest agent | ARSENAL MODE | plan approval | auto-pilot | auto reports"
                if ARSENAL else "read-only safe agent | plan approval | auto-pilot | auto reports")
    console.print(Panel(art, title="NIMROD v1.2", subtitle=subtitle,
                        border_style="red" if ARSENAL else "magenta"))


def main():
    global MODE, LAST_INV, CMD_TIMEOUT, MODEL, ARSENAL, SCOPE, MAX_JOBS, SEQUENTIAL
    args = parse_args()

    if args.safe:
        ARSENAL = False
    elif args.arsenal:
        ARSENAL = True
    if args.scope is not None:
        SCOPE = args.scope.strip()

    if args.timeout and args.timeout > 0:
        CMD_TIMEOUT = args.timeout
    if args.jobs is not None:
        MAX_JOBS = args.jobs
    if args.sequential:
        SEQUENTIAL = True
    if args.model:
        MODEL = args.model
    if args.api_base:
        global API_BASE
        API_BASE = args.api_base
        global client
        client = make_client()

    if args.ping:
        banner()
        sys.exit(ping_chain())

    if args.engine_waker:
        sys.exit(wake_engine())

    banner()
    if ARSENAL:
        console.print(Panel(
            "[bold red]ARSENAL MODE[/bold red] - reconnaissance, exploitation, credential, wireless, "
            "AD and post-exploitation tools are permitted.\n"
            "Only use NIMROD against systems you own or have written authorization to test.\n"
            "Authorized scope: [bold]" + (SCOPE or "(not set - use --scope or /scope)") + "[/bold]",
            title="AUTHORIZATION REQUIRED", border_style="red"))
    warmup_engine()
    start_keepalive()

    if args.mode:
        MODE = args.mode.upper()
    else:
        while True:
            try:
                m = console.input("[bold cyan]select mode[/bold cyan] [R]ED / [B]LUE / [P]URPLE (exit to quit) > ").strip().upper()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[bold magenta]NIMROD out.[/bold magenta]")
                sys.exit(0)
            if m in ("EXIT", "QUIT", "Q"):
                console.print("[bold magenta]NIMROD out.[/bold magenta]")
                sys.exit(0)
            if m in ("R", "RED"):
                MODE = "RED"; break
            if m in ("B", "BLUE"):
                MODE = "BLUE"; break
            if m in ("P", "PURPLE", ""):
                MODE = "PURPLE"; break

    directive = args.directive or ""
    if not args.no_auto and not directive:
        try:
            directive = console.input("[bold cyan]mission directive[/bold cyan] (enter = skip to chat, exit to quit) > ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold magenta]NIMROD out.[/bold magenta]")
            sys.exit(0)
        if directive.upper() in ("EXIT", "QUIT", "Q"):
            console.print("[bold magenta]NIMROD out.[/bold magenta]")
            sys.exit(0)

    LAST_INV = auto_recon()
    history = [{"role": "system", "content": make_system(MODE)}]
    if directive and not args.no_auto:
        console.print(Panel("[bold cyan]PHASE 2: BUILDING MISSION FRAMEWORK FROM DEVICE RESOURCES...[/bold cyan]"))
        with console.status("[bold magenta]NIMROD is thinking — building mission plan...[/bold magenta]", spinner="dots"):
            plan = generate_plan(LAST_INV, directive)
        if plan:
            run_mission(plan, history)
        else:
            console.print("[red]plan engine unavailable; falling back to interactive chat.[/red]")
            chat_turn(history, "Directive: " + directive + ". Propose the first recon step.")
    interactive(history)
    console.print("[bold magenta]NIMROD out.[/bold magenta]")

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold magenta]NIMROD out.[/bold magenta]")
        sys.exit(0)



