import subprocess
import os
import time
import sys
import threading
import re
import json
import requests
import shutil
from datetime import datetime
from pathlib import Path
import uuid
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter.font import Font
import tkinter.font as tkFont
from threading import Thread
import queue
import random
import psutil
from collections import deque
from enum import Enum

# ========== 1. إعداد متغيرات API ==========
API_KEYS = [
    "API_KEY_1",
    "API_KEY_2",
    "API_KEY_3"
]
API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "deepseek-coder"
active_key_index = 0

# ========== 2. تقسيم الأدوات ==========
RECON = [
    "nmap", "masscan", "amass", "sublist3r", "theHarvester", "whatweb", "wafw00f", "dnsenum", "dnsrecon", "fierce"
]
ENUM = [
    "enum4linux", "nbtscan", "smbclient", "crackmapexec", "smbmap", "rpcclient"
]
DIR_ENUM = [
    "dirb", "dirsearch", "ffuf", "gobuster", "wfuzz"
]
VULN = [
    "nikto", "wpscan", "joomscan", "droopescan", "sqlmap", "bbqsql", "sqlninja", "jexboss", "xsser", "arachni",
    "wapiti", "zaproxy", "skipfish", "nuclei"
]
EXPLOIT = [
    "hydra", "medusa", "patator", "ncrack", "john", "hashcat", "metasploit", "msfvenom", "routersploit", "searchsploit"
]
ALL_TOOLS = RECON + ENUM + DIR_ENUM + VULN + EXPLOIT

# Tool resource profiles (CPU%, RAM MB, estimated duration seconds)
TOOL_RESOURCES = {
    "nmap": {"cpu": 30, "ram": 100, "duration": 120, "priority": 1},
    "masscan": {"cpu": 80, "ram": 150, "duration": 300, "priority": 1},
    "amass": {"cpu": 40, "ram": 200, "duration": 180, "priority": 2},
    "sublist3r": {"cpu": 20, "ram": 80, "duration": 60, "priority": 2},
    "theHarvester": {"cpu": 15, "ram": 70, "duration": 90, "priority": 3},
    "whatweb": {"cpu": 10, "ram": 50, "duration": 30, "priority": 3},
    "wafw00f": {"cpu": 10, "ram": 40, "duration": 20, "priority": 3},
    "dnsenum": {"cpu": 15, "ram": 60, "duration": 45, "priority": 2},
    "dnsrecon": {"cpu": 20, "ram": 80, "duration": 60, "priority": 2},
    "fierce": {"cpu": 15, "ram": 60, "duration": 50, "priority": 3},
    "nikto": {"cpu": 25, "ram": 100, "duration": 180, "priority": 2},
    "wpscan": {"cpu": 20, "ram": 90, "duration": 120, "priority": 2},
    "sqlmap": {"cpu": 30, "ram": 120, "duration": 300, "priority": 1},
    "nuclei": {"cpu": 40, "ram": 150, "duration": 120, "priority": 1},
    "dirb": {"cpu": 20, "ram": 70, "duration": 180, "priority": 2},
    "dirsearch": {"cpu": 25, "ram": 80, "duration": 150, "priority": 2},
    "ffuf": {"cpu": 30, "ram": 100, "duration": 120, "priority": 2},
    "gobuster": {"cpu": 25, "ram": 90, "duration": 100, "priority": 2},
    "wfuzz": {"cpu": 25, "ram": 85, "duration": 110, "priority": 2},
    "hydra": {"cpu": 50, "ram": 120, "duration": 600, "priority": 1},
    "metasploit": {"cpu": 40, "ram": 300, "duration": 180, "priority": 1},
    # Add default for unknown tools
    "default": {"cpu": 20, "ram": 80, "duration": 120, "priority": 3}
}

class ToolStatus(Enum):
    PENDING = "⏳ PENDING"
    RUNNING = "⚡ RUNNING"
    COMPLETED = "✅ COMPLETED"
    FAILED = "❌ FAILED"
    QUEUED = "📋 QUEUED"

TOOLS_COMMANDS = {
    "nmap": "nmap -A {TARGET} -oN nmap.txt",
    "masscan": "masscan {TARGET} -p1-65535 --rate=1000 -oL masscan.txt",
    "amass": "amass enum -d {TARGET} -o amass.txt",
    "sublist3r": "sublist3r -d {TARGET} -o sublist3r.txt",
    "theHarvester": "theHarvester -d {TARGET} -b all -f harvester.html",
    "whatweb": "whatweb {TARGET} > whatweb.txt",
    "wafw00f": "wafw00f {TARGET} > wafw00f.txt",
    "nikto": "nikto -host {TARGET} -output nikto.txt",
    "dirb": "dirb http://{TARGET} -o dirb.txt",
    "dirsearch": "dirsearch -u http://{TARGET} -o dirsearch.txt",
    "ffuf": "ffuf -u http://{TARGET}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o ffuf.json",
    "gobuster": "gobuster dir -u http://{TARGET} -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt",
    "wpscan": "wpscan --url http://{TARGET} --no-update -o wpscan.txt",
    "joomscan": "joomscan --url http://{TARGET} > joomscan.txt",
    "dnsenum": "dnsenum {TARGET} > dnsenum.txt",
    "dnsrecon": "dnsrecon -d {TARGET} -a -j dnsrecon.json",
    "fierce": "fierce --domain {TARGET} > fierce.txt",
    "enum4linux": "enum4linux -a {TARGET} > enum4linux.txt",
    "nbtscan": "nbtscan {TARGET} > nbtscan.txt",
    "smbclient": "smbclient -L //{TARGET} -N > smbclient.txt",
    "crackmapexec": "crackmapexec smb {TARGET} > cme.txt",
    "smbmap": "smbmap -H {TARGET} > smbmap.txt",
    "rpcclient": "rpcclient -U '' {TARGET} > rpcclient.txt",
    "hydra": "hydra -L users.txt -P passwords.txt {TARGET} ssh > hydra.txt",
    "medusa": "medusa -h {TARGET} -U users.txt -P passwords.txt -M ssh > medusa.txt",
    "patator": "patator ssh_login host={TARGET} user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Authentication failed.' > patator.txt",
    "ncrack": "ncrack -p 22 --user root -P passwords.txt {TARGET} -oN ncrack.txt",
    "john": "john --wordlist=passwords.txt hashes.txt > john.txt",
    "hashcat": "hashcat -m 0 -a 0 hashes.txt passwords.txt > hashcat.txt",
    "sqlmap": "sqlmap -u \"http://{TARGET}\" --batch --output-dir=sqlmap",
    "bbqsql": "bbqsql -u \"http://{TARGET}\"",
    "sqlninja": "sqlninja -u \"http://{TARGET}\"",
    "jexboss": "jexboss -u http://{TARGET} > jexboss.txt",
    "xsser": "xsser --url http://{TARGET} > xsser.txt",
    "arachni": "arachni http://{TARGET} --report-save=arachni.afr",
    "wapiti": "wapiti http://{TARGET} -f html -o wapiti.html",
    "zaproxy": "zaproxy -cmd -quickurl http://{TARGET} -quickout zap.txt",
    "skipfish": "skipfish -o skipfish http://{TARGET}",
    "nuclei": "nuclei -u http://{TARGET} -o nuclei.txt",
    "metasploit": "msfconsole -q -x 'db_nmap {TARGET}; exit' > metasploit.txt",
    "msfvenom": "msfvenom -p windows/meterpreter/reverse_tcp LHOST={TARGET} LPORT=4444 -f exe > payload.exe",
    "routersploit": "rsf.py > routersploit.txt",
    "searchsploit": "searchsploit {TARGET} > searchsploit.txt"
}

# ========== 3. برومبت الذكاء الاصطناعي ==========
SYSTEM_PROMPT = f"""
أنت وكيل ذكاء اصطناعي متقدم في اختبار الاختراق.
بعد كل فحص، سيصلك تقرير دمج ضخم (بصيغة JSON) يحوي نتائج أدوات ركون، جمع معلومات، فحص ثغرات، واستغلالات (من أدوات كالي مثل: {'، '.join(RECON + VULN[:5])} وغيرها).

- حلل النتائج بعمق.
- استخرج CVEs، التوصيات، نقاط الاستغلال، والأدوات الأنسب للمرحلة القادمة.
- لا تكتب شرح عام أو اقتراحات نصية، أعطني أوامر صريحة (bash, python, git, pip, ...).
- كل أمر في سطر خاص، ولا تكرر الأوامر أو تعيد نفس الأداة دون داعٍ.
- إذا احتجت أدوات جديدة أو POC حملها مباشرة (git clone, pip install...).
- إذا لاحظت ثغرة حرجة أو استغلال ممكن، صرح بذلك وحدد كيف يتم الاستغلال.

أرسل الأوامر بهذا الشكل:
<COMMANDS>
nmap -A target.com -oN nmap.txt
git clone https://github.com/blabla.git
python exploit.py --target target.com
</COMMANDS>

ثم أرسل ملف قرار (JSON) يوصف المرحلة القادمة بهذا الشكل:
<DECISION>
{{
  "phase": "post-scan",
  "priority_tools": ["sqlmap", "nuclei", "wpscan"],
  "next_action": "exploit"
}}
</DECISION>
"""

# ========== 4. اكتشاف التيرمنال المناسب ==========
def find_terminal_emulator():
    candidates = [
        "x-terminal-emulator", "xfce4-terminal", "konsole",
        "xterm", "mate-terminal", "tilix", "lxterminal", "eterm", "alacritty", "kitty", "gnome-terminal"
    ]
    for term in candidates:
        if shutil.which(term):
            return term
    return None

TERMINAL = find_terminal_emulator()

def run_command_in_new_terminal(cmd, cwd=None, tool=None, error_log=None):
    try:
        if not TERMINAL:
            subprocess.Popen(cmd, shell=True, cwd=cwd)
            return
        if cwd is None:
            cwd = os.getcwd()
        args = []
        if "konsole" in TERMINAL:
            args = [TERMINAL, "-e", f"bash -c '{cmd}; exec bash'"]
        elif "xterm" in TERMINAL or "eterm" in TERMINAL or "x-terminal-emulator" in TERMINAL:
            args = [TERMINAL, "-e", f"bash -c \"{cmd}; exec bash\""]
        elif "tilix" in TERMINAL or "lxterminal" in TERMINAL or "mate-terminal" in TERMINAL:
            args = [TERMINAL, "-e", f"bash -c '{cmd}; exec bash'"]
        elif "alacritty" in TERMINAL or "kitty" in TERMINAL:
            args = [TERMINAL, "-e", f"bash -c '{cmd}; exec bash'"]
        elif "gnome-terminal" in TERMINAL:
            args = [TERMINAL, "--", "bash", "-c", f"{cmd}; exec bash"]
        else:
            args = [TERMINAL, "-e", f"bash -c '{cmd}; exec bash'"]
        subprocess.Popen(args, cwd=cwd)
    except Exception as e:
        if error_log and tool:
            with open(error_log, "a") as log:
                log.write(f"[{tool}] Error: {e}\n")

def query_ai(messages):
    global active_key_index
    tries = 0
    while tries < len(API_KEYS):
        headers = {
            "Authorization": f"Bearer {API_KEYS[active_key_index]}",
            "Content-Type": "application/json"
        }
        data = {
            "model": MODEL,
            "messages": messages,
            "temperature": 0.18
        }
        try:
            response = requests.post(API_URL, headers=headers, json=data, timeout=180)
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            elif response.status_code == 429:
                active_key_index = (active_key_index + 1) % len(API_KEYS)
                tries += 1
                print(f"[!] تبديل مفتاح API...")
                time.sleep(2)
            else:
                print(f"\n[!] خطأ في الاتصال: {response.status_code}")
                print(response.text)
                return None
        except Exception as e:
            print(f"\n[!] فشل الاتصال: {e}")
            active_key_index = (active_key_index + 1) % len(API_KEYS)
            tries += 1
            time.sleep(2)
    print("[!] جميع مفاتيح OpenRouter منتهية أو معطلة.")
    return None

def substitute_target(cmd, target):
    return cmd.replace("{TARGET}", target)

# ========== 5. استخراج الأوامر وتحليل الرد الذكي ==========
def extract_commands_and_decision(ai_response):
    cmds, decision_json = [], None
    in_commands, in_decision = False, False
    for line in ai_response.splitlines():
        line = line.strip()
        if line.startswith("<COMMANDS>"):
            in_commands = True
            continue
        if line.startswith("</COMMANDS>"):
            in_commands = False
            continue
        if line.startswith("<DECISION>"):
            in_decision = True
            decision_lines = []
            continue
        if line.startswith("</DECISION>"):
            in_decision = False
            try:
                decision_json = json.loads('\n'.join(decision_lines))
            except Exception:
                decision_json = None
            continue
        if in_commands:
            # تحليل ذكي: فقط أوامر تبدأ بواحد من البادئات المعروفة
            if re.match(r'^(git clone|apt-get|pip install|go install|bash|python|nmap|sqlmap|ffuf|gobuster|wpscan|dirsearch|nikto|nuclei|hydra|msfconsole|metasploit|arachni|wapiti|zaproxy|skipfish)', line):
                cmds.append(line)
        if in_decision:
            decision_lines.append(line)
    return cmds, decision_json

# ========== 6. تحسين دمج التقارير (JSON) ==========
def merge_reports_json(workdir, merged_report_path):
    results = {}
    for file in Path(workdir).glob("*.*"):
        if file.name in ["report.json", "errors.log"]:
            continue
        try:
            with open(file, "r", errors="ignore") as f:
                results[file.name] = f.read()[:30000]  # لا تدمج ملفات ضخمة كاملة
        except Exception as e:
            results[file.name] = f"ERROR: {e}"
    with open(merged_report_path, "w") as out:
        json.dump(results, out, indent=2, ensure_ascii=False)
    print(f"[+] تم دمج كل نتائج الفحص في: {merged_report_path}")

# ========== 7. wait_for_tools مع فحص ملفات ==========
def wait_for_tools(tools, workdir, timeout=1800):
    start = time.time()
    print("[*] انتظار اكتمال ملفات الأدوات ...")
    # توقع أن كل أداة تكتب ملفها باسمها، أو يوجد ملف done.txt
    while time.time() - start < timeout:
        all_done = True
        for tool in tools:
            expected = None
            for ext in [".txt", ".json", ".html", ".log"]:
                fname = Path(workdir) / f"{tool}{ext}"
                if fname.exists():
                    expected = fname
                    break
            if not expected:
                all_done = False
                break
        if all_done:
            print("[+] كل الأدوات أنهت مهامها.")
            return
        time.sleep(12)
    print("[!] انتهت المهلة، بعض الأدوات لم تكتمل.")

# ========== 8. كشف CVE من nmap وnuclei ==========
def extract_cves_from_reports(merged_json_path):
    cves = set()
    if not os.path.exists(merged_json_path): return []
    with open(merged_json_path, "r", errors="ignore") as f:
        data = json.load(f)
    for fname, content in data.items():
        found = re.findall(r'CVE-\d{4}-\d{4,7}', content)
        cves.update(found)
    return sorted(list(cves))

# ========== 9. فلترة الأوامر الخطيرة ==========
def is_safe_command(cmd):
    dangerous = [
        r"rm\s", r"dd\s", r"mkfs", r":(){:|:&};:", r"shutdown", r"reboot", r"poweroff", r"mv\s", r"kill", r"chown", r"chmod\s+777"
    ]
    for pat in dangerous:
        if re.search(pat, cmd):
            return False
    return True

# ========== 10. نظام التحكم في الجولات ==========
def get_next_tools(decision_json):
    if not decision_json or "priority_tools" not in decision_json:
        return []
    return [t for t in decision_json["priority_tools"] if t in ALL_TOOLS]

# ========== 10.5. Resource Monitor & Queue Manager ==========
class ResourceMonitor:
    """Monitor system resources in real-time"""
    
    def __init__(self, cpu_threshold=70, ram_threshold=75):
        self.cpu_threshold = cpu_threshold
        self.ram_threshold = ram_threshold
        
    def get_current_usage(self):
        """Get current CPU and RAM usage"""
        cpu_percent = psutil.cpu_percent(interval=1)
        ram_percent = psutil.virtual_memory().percent
        ram_available_mb = psutil.virtual_memory().available / (1024 * 1024)
        return {
            'cpu_percent': cpu_percent,
            'ram_percent': ram_percent,
            'ram_available_mb': ram_available_mb
        }
    
    def can_run_tool(self, tool_name):
        """Check if system has enough resources to run a tool"""
        usage = self.get_current_usage()
        tool_resources = TOOL_RESOURCES.get(tool_name, TOOL_RESOURCES["default"])
        
        # Check if adding this tool would exceed thresholds
        if usage['cpu_percent'] + tool_resources['cpu'] > self.cpu_threshold:
            return False, "CPU threshold exceeded"
        
        if usage['ram_available_mb'] < tool_resources['ram']:
            return False, "Insufficient RAM"
        
        return True, "Resources available"
    
    def get_system_info(self):
        """Get detailed system information"""
        return {
            'cpu_count': psutil.cpu_count(),
            'total_ram_gb': psutil.virtual_memory().total / (1024**3),
            'cpu_percent': psutil.cpu_percent(interval=0.5),
            'ram_percent': psutil.virtual_memory().percent
        }

class ToolQueueManager:
    """Manage tool execution queue with resource awareness"""
    
    def __init__(self, max_concurrent=2, resource_monitor=None):
        self.max_concurrent = max_concurrent
        self.resource_monitor = resource_monitor or ResourceMonitor()
        self.queue = deque()
        self.running_tools = {}
        self.completed_tools = {}
        self.failed_tools = {}
        self.lock = threading.Lock()
        self.status_callback = None
        
    def set_status_callback(self, callback):
        """Set callback for status updates"""
        self.status_callback = callback
        
    def add_tool(self, tool_name, command, workdir, error_log):
        """Add a tool to the queue"""
        with self.lock:
            tool_info = {
                'name': tool_name,
                'command': command,
                'workdir': workdir,
                'error_log': error_log,
                'status': ToolStatus.QUEUED,
                'start_time': None,
                'end_time': None,
                'resources': TOOL_RESOURCES.get(tool_name, TOOL_RESOURCES["default"])
            }
            self.queue.append(tool_info)
            self._notify_status(tool_name, ToolStatus.QUEUED)
    
    def get_running_count(self):
        """Get number of currently running tools"""
        with self.lock:
            return len(self.running_tools)
    
    def can_start_new_tool(self):
        """Check if we can start a new tool"""
        with self.lock:
            if len(self.running_tools) >= self.max_concurrent:
                return False, "Max concurrent limit reached"
            
            if not self.queue:
                return False, "Queue is empty"
            
            # Check the next tool in queue
            next_tool = self.queue[0]
            can_run, reason = self.resource_monitor.can_run_tool(next_tool['name'])
            return can_run, reason
    
    def start_next_tool(self):
        """Start the next tool from queue if possible"""
        with self.lock:
            if not self.queue:
                return None
            
            if len(self.running_tools) >= self.max_concurrent:
                return None
            
            tool_info = self.queue.popleft()
            can_run, reason = self.resource_monitor.can_run_tool(tool_info['name'])
            
            if not can_run:
                # Put it back at the front of queue
                self.queue.appendleft(tool_info)
                return None
            
            tool_info['status'] = ToolStatus.RUNNING
            tool_info['start_time'] = datetime.now()
            self.running_tools[tool_info['name']] = tool_info
            self._notify_status(tool_info['name'], ToolStatus.RUNNING)
            
            # Start tool in separate thread
            thread = threading.Thread(
                target=self._execute_tool,
                args=(tool_info,),
                daemon=True
            )
            thread.start()
            
            return tool_info['name']
    
    def _execute_tool(self, tool_info):
        """Execute a tool and handle completion"""
        try:
            # Run the command
            run_command_in_new_terminal(
                tool_info['command'],
                tool_info['workdir'],
                tool_info['name'],
                tool_info['error_log']
            )
            
            # Wait for tool to complete (check for output file)
            self._wait_for_tool_completion(tool_info)
            
            # Mark as completed
            with self.lock:
                tool_info['status'] = ToolStatus.COMPLETED
                tool_info['end_time'] = datetime.now()
                if tool_info['name'] in self.running_tools:
                    del self.running_tools[tool_info['name']]
                self.completed_tools[tool_info['name']] = tool_info
                self._notify_status(tool_info['name'], ToolStatus.COMPLETED)
            
        except Exception as e:
            # Mark as failed
            with self.lock:
                tool_info['status'] = ToolStatus.FAILED
                tool_info['end_time'] = datetime.now()
                tool_info['error'] = str(e)
                if tool_info['name'] in self.running_tools:
                    del self.running_tools[tool_info['name']]
                self.failed_tools[tool_info['name']] = tool_info
                self._notify_status(tool_info['name'], ToolStatus.FAILED)
    
    def _wait_for_tool_completion(self, tool_info):
        """Wait for tool to complete by checking output file"""
        max_wait = tool_info['resources']['duration'] + 60
        start = time.time()
        
        while time.time() - start < max_wait:
            # Check if output file exists
            for ext in [".txt", ".json", ".html", ".log"]:
                output_file = Path(tool_info['workdir']) / f"{tool_info['name']}{ext}"
                if output_file.exists():
                    time.sleep(5)  # Wait a bit more to ensure file is written
                    return
            time.sleep(10)
    
    def _notify_status(self, tool_name, status):
        """Notify status change via callback"""
        if self.status_callback:
            self.status_callback(tool_name, status)
    
    def get_queue_status(self):
        """Get complete queue status"""
        with self.lock:
            return {
                'queued': list(self.queue),
                'running': dict(self.running_tools),
                'completed': dict(self.completed_tools),
                'failed': dict(self.failed_tools),
                'total': len(self.queue) + len(self.running_tools) + len(self.completed_tools) + len(self.failed_tools)
            }
    
    def is_all_complete(self):
        """Check if all tools are complete"""
        with self.lock:
            return len(self.queue) == 0 and len(self.running_tools) == 0

# ========== 11. Cyberpunk GUI Class ==========
class CyberpunkPentestGUI:
    def __init__(self):
        self.root = tk.Tk()
        # Initialize variables BEFORE creating widgets
        self.message_queue = queue.Queue()
        self.scanning = False
        self.scan_thread = None
        self.dashboard = {"rounds": []}
        self.target = ""
        self.session_id = ""
        self.root_workdir = ""
        
        # Resource monitoring and queue management
        self.resource_monitor = ResourceMonitor(cpu_threshold=70, ram_threshold=75)
        self.tool_queue_manager = None
        self.max_concurrent_tools = 2
        self.resource_update_interval = 2000  # ms
        
        # Now setup theme and create widgets
        self.setup_cyberpunk_theme()
        self.create_widgets()
        
        # Start resource monitoring
        self.update_resource_display()
        
    def setup_cyberpunk_theme(self):
        self.root.title("🚀 CYBERPUNK AI PENTEST AGENT 2077 🚀")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a0a')
        self.root.resizable(True, True)
        
        # Cyberpunk color scheme
        self.colors = {
            'bg_primary': '#0a0a0a',
            'bg_secondary': '#1a1a2e',
            'bg_tertiary': '#16213e',
            'neon_cyan': '#00ffff',
            'neon_pink': '#ff00ff',
            'neon_green': '#00ff00',
            'neon_red': '#ff0080',
            'neon_yellow': '#ffff00',
            'neon_blue': '#0080ff',
            'text_primary': '#ffffff',
            'text_secondary': '#b0b0b0',
            'warning': '#ff4444',
            'success': '#44ff44'
        }
        
        # Custom fonts
        self.fonts = {
            'title': tkFont.Font(family="Consolas", size=16, weight="bold"),
            'subtitle': tkFont.Font(family="Consolas", size=12, weight="bold"),
            'body': tkFont.Font(family="Consolas", size=10),
            'console': tkFont.Font(family="Courier New", size=9),
            'button': tkFont.Font(family="Consolas", size=11, weight="bold")
        }
        
    def create_widgets(self):
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title with animated effect
        title_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.title_label = tk.Label(
            title_frame,
            text="🚀 CYBERPUNK AI PENTEST AGENT 2077 🚀",
            font=self.fonts['title'],
            fg=self.colors['neon_cyan'],
            bg=self.colors['bg_primary']
        )
        self.title_label.pack()
        
        # Status bar
        self.status_label = tk.Label(
            title_frame,
            text="SYSTEM READY • NEURAL NETWORK ONLINE • AWAITING TARGET",
            font=self.fonts['body'],
            fg=self.colors['neon_green'],
            bg=self.colors['bg_primary']
        )
        self.status_label.pack(pady=(5, 0))
        
        # Left panel - Controls
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'], relief=tk.RAISED, bd=2)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Target input
        target_frame = tk.LabelFrame(
            left_frame,
            text="🎯 TARGET ACQUISITION",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_pink'],
            bg=self.colors['bg_secondary'],
            labelanchor=tk.N
        )
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            target_frame,
            text="Target IP/Domain:",
            font=self.fonts['body'],
            fg=self.colors['text_primary'],
            bg=self.colors['bg_secondary']
        ).pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        self.target_entry = tk.Entry(
            target_frame,
            font=self.fonts['body'],
            bg=self.colors['bg_tertiary'],
            fg=self.colors['neon_cyan'],
            insertbackground=self.colors['neon_cyan'],
            relief=tk.FLAT,
            bd=2
        )
        self.target_entry.pack(fill=tk.X, padx=5, pady=5)
        
        # Control buttons
        control_frame = tk.LabelFrame(
            left_frame,
            text="🎮 CONTROL MATRIX",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_green'],
            bg=self.colors['bg_secondary'],
            labelanchor=tk.N
        )
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_button = tk.Button(
            control_frame,
            text="▶ INITIATE SCAN",
            font=self.fonts['button'],
            bg=self.colors['neon_green'],
            fg=self.colors['bg_primary'],
            activebackground=self.colors['success'],
            activeforeground=self.colors['bg_primary'],
            relief=tk.FLAT,
            command=self.start_scan,
            cursor="hand2"
        )
        self.start_button.pack(fill=tk.X, padx=5, pady=5)
        
        self.stop_button = tk.Button(
            control_frame,
            text="⏹ TERMINATE",
            font=self.fonts['button'],
            bg=self.colors['neon_red'],
            fg=self.colors['text_primary'],
            activebackground=self.colors['warning'],
            activeforeground=self.colors['text_primary'],
            relief=tk.FLAT,
            command=self.stop_scan,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.stop_button.pack(fill=tk.X, padx=5, pady=5)
        
        self.save_button = tk.Button(
            control_frame,
            text="💾 EXPORT LOGS",
            font=self.fonts['button'],
            bg=self.colors['neon_blue'],
            fg=self.colors['text_primary'],
            activebackground=self.colors['neon_cyan'],
            activeforeground=self.colors['bg_primary'],
            relief=tk.FLAT,
            command=self.save_report,
            cursor="hand2"
        )
        self.save_button.pack(fill=tk.X, padx=5, pady=5)
        
        # Settings frame for concurrent tools
        settings_frame = tk.LabelFrame(
            left_frame,
            text="⚙️ SETTINGS",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_yellow'],
            bg=self.colors['bg_secondary'],
            labelanchor=tk.N
        )
        settings_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            settings_frame,
            text="Max Concurrent Tools:",
            font=self.fonts['body'],
            fg=self.colors['text_primary'],
            bg=self.colors['bg_secondary']
        ).pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        concurrent_frame = tk.Frame(settings_frame, bg=self.colors['bg_secondary'])
        concurrent_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.concurrent_var = tk.IntVar(value=2)
        for i in range(1, 4):
            rb = tk.Radiobutton(
                concurrent_frame,
                text=str(i),
                variable=self.concurrent_var,
                value=i,
                font=self.fonts['body'],
                fg=self.colors['text_secondary'],
                bg=self.colors['bg_secondary'],
                selectcolor=self.colors['bg_tertiary'],
                activebackground=self.colors['bg_secondary'],
                activeforeground=self.colors['neon_green'],
                command=self.update_concurrent_limit
            )
            rb.pack(side=tk.LEFT, padx=5)
        
        # Resource thresholds
        tk.Label(
            settings_frame,
            text="CPU Threshold (%):",
            font=self.fonts['body'],
            fg=self.colors['text_primary'],
            bg=self.colors['bg_secondary']
        ).pack(anchor=tk.W, padx=5, pady=(10, 0))
        
        self.cpu_threshold_var = tk.IntVar(value=70)
        cpu_scale = tk.Scale(
            settings_frame,
            from_=50,
            to=90,
            orient=tk.HORIZONTAL,
            variable=self.cpu_threshold_var,
            font=self.fonts['body'],
            fg=self.colors['neon_cyan'],
            bg=self.colors['bg_tertiary'],
            troughcolor=self.colors['bg_primary'],
            activebackground=self.colors['neon_cyan'],
            highlightthickness=0
        )
        cpu_scale.pack(fill=tk.X, padx=5, pady=2)
        
        tk.Label(
            settings_frame,
            text="RAM Threshold (%):",
            font=self.fonts['body'],
            fg=self.colors['text_primary'],
            bg=self.colors['bg_secondary']
        ).pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        self.ram_threshold_var = tk.IntVar(value=75)
        ram_scale = tk.Scale(
            settings_frame,
            from_=50,
            to=90,
            orient=tk.HORIZONTAL,
            variable=self.ram_threshold_var,
            font=self.fonts['body'],
            fg=self.colors['neon_pink'],
            bg=self.colors['bg_tertiary'],
            troughcolor=self.colors['bg_primary'],
            activebackground=self.colors['neon_pink'],
            highlightthickness=0
        )
        ram_scale.pack(fill=tk.X, padx=5, pady=2)
        
        # Tools selection
        tools_frame = tk.LabelFrame(
            left_frame,
            text="🔧 TOOL ARSENAL",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_yellow'],
            bg=self.colors['bg_secondary'],
            labelanchor=tk.N
        )
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tool categories with checkboxes
        self.tool_vars = {}
        categories = {
            "RECONNAISSANCE": RECON[:5],
            "ENUMERATION": ENUM[:3],
            "VULNERABILITY": VULN[:5],
            "EXPLOITATION": EXPLOIT[:3]
        }
        
        for category, tools in categories.items():
            cat_frame = tk.LabelFrame(
                tools_frame,
                text=category,
                font=self.fonts['body'],
                fg=self.colors['neon_cyan'],
                bg=self.colors['bg_secondary']
            )
            cat_frame.pack(fill=tk.X, padx=5, pady=2)
            
            for tool in tools:
                var = tk.BooleanVar(value=True)
                self.tool_vars[tool] = var
                cb = tk.Checkbutton(
                    cat_frame,
                    text=tool,
                    variable=var,
                    font=self.fonts['body'],
                    fg=self.colors['text_secondary'],
                    bg=self.colors['bg_secondary'],
                    selectcolor=self.colors['bg_tertiary'],
                    activebackground=self.colors['bg_secondary'],
                    activeforeground=self.colors['neon_green']
                )
                cb.pack(anchor=tk.W, padx=5, pady=1)
        
        # Right panel - Output
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Resource monitor display
        resource_frame = tk.LabelFrame(
            right_frame,
            text="🖥️ SYSTEM RESOURCES",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_cyan'],
            bg=self.colors['bg_primary'],
            labelanchor=tk.N
        )
        resource_frame.pack(fill=tk.X, pady=(0, 5))
        
        resource_grid = tk.Frame(resource_frame, bg=self.colors['bg_primary'])
        resource_grid.pack(fill=tk.X, padx=5, pady=5)
        
        # CPU Usage
        tk.Label(
            resource_grid,
            text="CPU:",
            font=self.fonts['body'],
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_primary']
        ).grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.cpu_label = tk.Label(
            resource_grid,
            text="0%",
            font=self.fonts['body'],
            fg=self.colors['neon_green'],
            bg=self.colors['bg_primary']
        )
        self.cpu_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.cpu_bar = ttk.Progressbar(
            resource_grid,
            length=150,
            mode='determinate',
            style='CPU.Horizontal.TProgressbar'
        )
        self.cpu_bar.grid(row=0, column=2, sticky=tk.W, padx=5)
        
        # RAM Usage
        tk.Label(
            resource_grid,
            text="RAM:",
            font=self.fonts['body'],
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_primary']
        ).grid(row=0, column=3, sticky=tk.W, padx=5)
        
        self.ram_label = tk.Label(
            resource_grid,
            text="0%",
            font=self.fonts['body'],
            fg=self.colors['neon_pink'],
            bg=self.colors['bg_primary']
        )
        self.ram_label.grid(row=0, column=4, sticky=tk.W, padx=5)
        
        self.ram_bar = ttk.Progressbar(
            resource_grid,
            length=150,
            mode='determinate',
            style='RAM.Horizontal.TProgressbar'
        )
        self.ram_bar.grid(row=0, column=5, sticky=tk.W, padx=5)
        
        # Tool Queue Display
        queue_frame = tk.LabelFrame(
            right_frame,
            text="📋 TOOL EXECUTION QUEUE",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_yellow'],
            bg=self.colors['bg_primary'],
            labelanchor=tk.N
        )
        queue_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Create a canvas with scrollbar for tool status
        queue_canvas_frame = tk.Frame(queue_frame, bg=self.colors['bg_tertiary'])
        queue_canvas_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.queue_text = scrolledtext.ScrolledText(
            queue_canvas_frame,
            font=self.fonts['console'],
            bg=self.colors['bg_tertiary'],
            fg=self.colors['neon_yellow'],
            height=6,
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.queue_text.pack(fill=tk.BOTH, expand=True)
        
        # Console output
        console_frame = tk.LabelFrame(
            right_frame,
            text="📱 NEURAL CONSOLE OUTPUT",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_pink'],
            bg=self.colors['bg_primary'],
            labelanchor=tk.N
        )
        console_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.console_text = scrolledtext.ScrolledText(
            console_frame,
            font=self.fonts['console'],
            bg=self.colors['bg_tertiary'],
            fg=self.colors['neon_green'],
            insertbackground=self.colors['neon_green'],
            selectbackground=self.colors['neon_cyan'],
            selectforeground=self.colors['bg_primary'],
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Progress and stats
        stats_frame = tk.LabelFrame(
            right_frame,
            text="📊 SCAN METRICS",
            font=self.fonts['subtitle'],
            fg=self.colors['neon_yellow'],
            bg=self.colors['bg_primary'],
            labelanchor=tk.N
        )
        stats_frame.pack(fill=tk.X, pady=(0, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(
            stats_frame,
            mode='indeterminate',
            style='Cyberpunk.Horizontal.TProgressbar'
        )
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        # Stats labels
        stats_grid = tk.Frame(stats_frame, bg=self.colors['bg_primary'])
        stats_grid.pack(fill=tk.X, padx=5, pady=5)
        
        self.stats_labels = {}
        stats_info = [
            ("Round:", "0"), ("Tools:", "0"), ("CVEs:", "0"), ("Status:", "IDLE")
        ]
        
        for i, (label, value) in enumerate(stats_info):
            row = i // 2
            col = i % 2
            
            tk.Label(
                stats_grid,
                text=label,
                font=self.fonts['body'],
                fg=self.colors['text_secondary'],
                bg=self.colors['bg_primary']
            ).grid(row=row, column=col*2, sticky=tk.W, padx=(0, 5))
            
            self.stats_labels[label.rstrip(':')] = tk.Label(
                stats_grid,
                text=value,
                font=self.fonts['body'],
                fg=self.colors['neon_cyan'],
                bg=self.colors['bg_primary']
            )
            self.stats_labels[label.rstrip(':')].grid(row=row, column=col*2+1, sticky=tk.W, padx=(0, 20))
        
        # Configure grid weights
        stats_grid.grid_columnconfigure(1, weight=1)
        stats_grid.grid_columnconfigure(3, weight=1)
        
        self.log_message("🚀 CYBERPUNK AI PENTEST AGENT INITIALIZED")
        self.log_message("💀 NEURAL NETWORKS ONLINE • READY FOR DIGITAL WARFARE")
        self.log_message("🎯 AWAITING TARGET COORDINATES...")
        
        # Display system info
        sys_info = self.resource_monitor.get_system_info()
        self.log_message(f"💻 SYSTEM: {sys_info['cpu_count']} CPUs | {sys_info['total_ram_gb']:.1f} GB RAM", self.colors['neon_blue'])
        
        # Start message processing
        self.process_messages()
        self.animate_title()
        
    def update_concurrent_limit(self):
        """Update the maximum concurrent tools limit"""
        self.max_concurrent_tools = self.concurrent_var.get()
        if self.tool_queue_manager:
            self.tool_queue_manager.max_concurrent = self.max_concurrent_tools
        self.log_message(f"⚙️ MAX CONCURRENT TOOLS SET TO: {self.max_concurrent_tools}", self.colors['neon_yellow'])
        
    def update_resource_display(self):
        """Update resource usage display"""
        try:
            # Update thresholds if changed
            self.resource_monitor.cpu_threshold = self.cpu_threshold_var.get()
            self.resource_monitor.ram_threshold = self.ram_threshold_var.get()
            
            usage = self.resource_monitor.get_current_usage()
            
            # Update CPU
            cpu_pct = usage['cpu_percent']
            self.cpu_label.configure(text=f"{cpu_pct:.1f}%")
            self.cpu_bar['value'] = cpu_pct
            
            # Color based on threshold
            if cpu_pct > self.resource_monitor.cpu_threshold:
                self.cpu_label.configure(fg=self.colors['neon_red'])
            elif cpu_pct > self.resource_monitor.cpu_threshold * 0.8:
                self.cpu_label.configure(fg=self.colors['neon_yellow'])
            else:
                self.cpu_label.configure(fg=self.colors['neon_green'])
            
            # Update RAM
            ram_pct = usage['ram_percent']
            self.ram_label.configure(text=f"{ram_pct:.1f}%")
            self.ram_bar['value'] = ram_pct
            
            # Color based on threshold
            if ram_pct > self.resource_monitor.ram_threshold:
                self.ram_label.configure(fg=self.colors['neon_red'])
            elif ram_pct > self.resource_monitor.ram_threshold * 0.8:
                self.ram_label.configure(fg=self.colors['neon_yellow'])
            else:
                self.ram_label.configure(fg=self.colors['neon_pink'])
            
            # Update queue display if manager exists
            if self.tool_queue_manager and self.scanning:
                self.update_queue_display()
            
        except Exception as e:
            pass  # Silently fail to avoid disrupting the app
        
        # Schedule next update
        self.root.after(self.resource_update_interval, self.update_resource_display)
        
    def update_queue_display(self):
        """Update the tool queue display"""
        if not self.tool_queue_manager:
            return
        
        status = self.tool_queue_manager.get_queue_status()
        
        self.queue_text.delete(1.0, tk.END)
        
        # Running tools
        if status['running']:
            self.queue_text.insert(tk.END, "⚡ RUNNING:\n", "running")
            for tool_name, tool_info in status['running'].items():
                elapsed = (datetime.now() - tool_info['start_time']).seconds
                self.queue_text.insert(tk.END, f"  • {tool_name} ({elapsed}s)\n")
        
        # Queued tools
        if status['queued']:
            self.queue_text.insert(tk.END, "\n📋 QUEUED:\n", "queued")
            for tool_info in list(status['queued'])[:5]:  # Show first 5
                self.queue_text.insert(tk.END, f"  • {tool_info['name']}\n")
            if len(status['queued']) > 5:
                self.queue_text.insert(tk.END, f"  ... and {len(status['queued']) - 5} more\n")
        
        # Completed tools
        if status['completed']:
            self.queue_text.insert(tk.END, f"\n✅ COMPLETED: {len(status['completed'])}\n", "completed")
        
        # Failed tools
        if status['failed']:
            self.queue_text.insert(tk.END, f"❌ FAILED: {len(status['failed'])}\n", "failed")
        
        # Apply colors
        self.queue_text.tag_config("running", foreground=self.colors['neon_yellow'])
        self.queue_text.tag_config("queued", foreground=self.colors['neon_cyan'])
        self.queue_text.tag_config("completed", foreground=self.colors['neon_green'])
        self.queue_text.tag_config("failed", foreground=self.colors['neon_red'])
        
    def tool_status_callback(self, tool_name, status):
        """Callback when tool status changes"""
        status_msg = f"{status.value} {tool_name}"
        
        if status == ToolStatus.RUNNING:
            color = self.colors['neon_yellow']
        elif status == ToolStatus.COMPLETED:
            color = self.colors['neon_green']
        elif status == ToolStatus.FAILED:
            color = self.colors['neon_red']
        else:
            color = self.colors['neon_cyan']
        
        self.message_queue.put(("log", status_msg, color))
        
    def animate_title(self):
        """Animate the title with cyberpunk effects"""
        colors = [self.colors['neon_cyan'], self.colors['neon_pink'], 
                 self.colors['neon_green'], self.colors['neon_yellow']]
        current_color = random.choice(colors)
        self.title_label.configure(fg=current_color)
        self.root.after(2000, self.animate_title)
        
    def log_message(self, message, color=None):
        """Add message to console with timestamp and color"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        self.console_text.insert(tk.END, formatted_msg)
        if color:
            # Apply color to the last inserted text
            start_line = int(self.console_text.index(tk.END).split('.')[0]) - 2
            self.console_text.tag_add(f"color_{color}", f"{start_line}.0", f"{start_line}.end")
            self.console_text.tag_config(f"color_{color}", foreground=color)
        
        self.console_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_stats(self, round_num=0, tools_count=0, cves_count=0, status="IDLE"):
        """Update the statistics display"""
        self.stats_labels["Round"].configure(text=str(round_num))
        self.stats_labels["Tools"].configure(text=str(tools_count))
        self.stats_labels["CVEs"].configure(text=str(cves_count))
        self.stats_labels["Status"].configure(text=status)
        
    def get_selected_tools(self):
        """Get list of selected tools"""
        selected = []
        for tool, var in self.tool_vars.items():
            if var.get():
                selected.append(tool)
        return selected
        
    def start_scan(self):
        """Start the penetration testing scan"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain!")
            return
            
        self.target = target
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4())[:8]
        self.root_workdir = os.path.abspath(f"AI_Pentest_{self.session_id}")
        
        self.scanning = True
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.progress.start()
        
        self.log_message(f"🎯 TARGET ACQUIRED: {target}", self.colors['neon_cyan'])
        self.log_message(f"📁 SESSION ID: {self.session_id}", self.colors['neon_yellow'])
        self.log_message("🚀 INITIATING CYBERPUNK SCAN SEQUENCE...", self.colors['neon_green'])
        
        self.update_stats(status="SCANNING")
        
        # Start scan in separate thread
        self.scan_thread = Thread(target=self.run_scan_process, daemon=True)
        self.scan_thread.start()
        
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.progress.stop()
        self.log_message("⚠ SCAN TERMINATED BY USER", self.colors['neon_red'])
        self.update_stats(status="TERMINATED")
        
    def save_report(self):
        """Save the scan report"""
        if not hasattr(self, 'root_workdir') or not os.path.exists(self.root_workdir):
            messagebox.showwarning("Warning", "No scan data available to save!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Cyberpunk Pentest Report"
        )
        
        if filename:
            try:
                final_report_path = os.path.join(self.root_workdir, "final_report.json")
                if os.path.exists(final_report_path):
                    shutil.copy2(final_report_path, filename)
                    self.log_message(f"💾 REPORT EXPORTED: {filename}", self.colors['neon_blue'])
                else:
                    messagebox.showerror("Error", "No final report found!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")
                
    def run_scan_process(self):
        """Main scan process running in separate thread with resource-aware queue management"""
        try:
            os.makedirs(self.root_workdir, exist_ok=True)
            error_log = os.path.join(self.root_workdir, "errors.log")
            
            # Initialize queue manager
            self.tool_queue_manager = ToolQueueManager(
                max_concurrent=self.max_concurrent_tools,
                resource_monitor=self.resource_monitor
            )
            self.tool_queue_manager.set_status_callback(self.tool_status_callback)
            
            selected_tools = self.get_selected_tools()
            if not selected_tools:
                selected_tools = RECON + DIR_ENUM + ["nikto", "wpscan", "sqlmap", "nuclei"]
            
            round_num = 1
            next_tools = selected_tools
            
            while round_num <= 5 and next_tools and self.scanning:
                round_dir = Path(self.root_workdir) / f"round_{round_num}"
                round_dir.mkdir(parents=True, exist_ok=True)
                
                self.message_queue.put(("log", f"🎮 INITIATING ROUND {round_num} | TOOLS: {', '.join(next_tools)}", self.colors['neon_pink']))
                self.message_queue.put(("stats", round_num, len(next_tools), 0, f"ROUND {round_num}"))
                
                # Add all tools to queue
                self.message_queue.put(("log", f"📋 ADDING {len(next_tools)} TOOLS TO QUEUE...", self.colors['neon_cyan']))
                
                for tool in next_tools:
                    if not self.scanning:
                        break
                        
                    cmd_template = TOOLS_COMMANDS.get(tool)
                    if not cmd_template:
                        continue
                        
                    cmd = substitute_target(cmd_template, self.target)
                    if not is_safe_command(cmd):
                        continue
                    
                    # Add to queue instead of running immediately
                    self.tool_queue_manager.add_tool(tool, cmd, str(round_dir), error_log)
                
                # Process queue with resource monitoring
                self.message_queue.put(("log", f"⚡ STARTING RESOURCE-AWARE TOOL EXECUTION (Max: {self.max_concurrent_tools} concurrent)", self.colors['neon_green']))
                
                while not self.tool_queue_manager.is_all_complete() and self.scanning:
                    # Try to start next tool
                    started = self.tool_queue_manager.start_next_tool()
                    
                    if started:
                        self.message_queue.put(("log", f"🚀 LAUNCHED: {started}", self.colors['neon_yellow']))
                    
                    # Wait before checking again
                    time.sleep(3)
                    
                    # Get current status
                    status = self.tool_queue_manager.get_queue_status()
                    running_count = len(status['running'])
                    
                    # Update stats
                    self.message_queue.put(("stats", round_num, running_count, 0, f"RUNNING: {running_count}"))
                
                if not self.scanning:
                    break
                
                # All tools completed for this round
                self.message_queue.put(("log", "✅ ALL TOOLS IN QUEUE COMPLETED", self.colors['neon_green']))
                
                # Merge reports and analyze
                merged_json_path = str(round_dir / "report.json")
                merge_reports_json(round_dir, merged_json_path)
                cves = extract_cves_from_reports(merged_json_path)
                
                if cves:
                    self.message_queue.put(("log", f"🚨 CVEs DISCOVERED: {cves}", self.colors['neon_red']))
                else:
                    self.message_queue.put(("log", "🔍 NO CRITICAL CVEs FOUND IN THIS ROUND", self.colors['neon_green']))
                
                # Update dashboard
                queue_status = self.tool_queue_manager.get_queue_status()
                round_data = {
                    "round": round_num,
                    "tools": next_tools,
                    "cves": cves,
                    "report": merged_json_path,
                    "timestamp": datetime.now().isoformat(),
                    "completed": len(queue_status['completed']),
                    "failed": len(queue_status['failed'])
                }
                self.dashboard["rounds"].append(round_data)
                
                total_cves = sum(len(r.get("cves", [])) for r in self.dashboard["rounds"])
                self.message_queue.put(("stats", round_num, len(next_tools), total_cves, f"ANALYZING"))
                
                # AI Analysis
                if self.scanning:
                    self.message_queue.put(("log", "🧠 NEURAL NETWORK ANALYZING RESULTS...", self.colors['neon_cyan']))
                    
                    with open(merged_json_path, "r", errors="ignore") as f:
                        report_json = f.read()
                        
                    messages = [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Analysis results JSON:\n\n{report_json}\n\nProvide next steps with explicit commands."}
                    ]
                    
                    ai_response = query_ai(messages)
                    if ai_response:
                        self.message_queue.put(("log", f"🤖 AI RESPONSE:\n{ai_response[:500]}...", self.colors['neon_blue']))
                        
                        cmds, decision_json = extract_commands_and_decision(ai_response)
                        
                        if decision_json:
                            with open(round_dir / "decision.json", "w") as f:
                                json.dump(decision_json, f, indent=2, ensure_ascii=False)
                            next_tools = get_next_tools(decision_json)
                        else:
                            next_tools = []
                            
                        # Execute AI commands (these run independently, not in queue)
                        for cmd in cmds[:3]:
                            if not is_safe_command(cmd) or not self.scanning:
                                continue
                            self.message_queue.put(("log", f"🎯 AI COMMAND: {cmd}", self.colors['neon_green']))
                            run_command_in_new_terminal(cmd, round_dir, tool="AI_CMD", error_log=error_log)
                            time.sleep(1)
                    else:
                        self.message_queue.put(("log", "❌ AI ANALYSIS FAILED", self.colors['neon_red']))
                        break
                
                # Reset queue manager for next round
                self.tool_queue_manager = ToolQueueManager(
                    max_concurrent=self.max_concurrent_tools,
                    resource_monitor=self.resource_monitor
                )
                self.tool_queue_manager.set_status_callback(self.tool_status_callback)
                
                round_num += 1
                
            # Final report
            if self.scanning:
                final_report = Path(self.root_workdir) / "final_report.json"
                self.dashboard["session_id"] = self.session_id
                self.dashboard["target"] = self.target
                self.dashboard["completed_at"] = datetime.now().isoformat()
                
                with open(final_report, "w") as f:
                    json.dump(self.dashboard, f, indent=2, ensure_ascii=False)
                
                all_cves = []
                for rnd in self.dashboard["rounds"]:
                    all_cves.extend(rnd.get("cves", []))
                
                self.message_queue.put(("log", "🎉 CYBERPUNK SCAN COMPLETED!", self.colors['neon_green']))
                self.message_queue.put(("log", f"📊 FINAL REPORT: {final_report}", self.colors['neon_cyan']))
                
                if all_cves:
                    unique_cves = sorted(set(all_cves))
                    self.message_queue.put(("log", f"🚨 TOTAL CVEs DISCOVERED: {unique_cves}", self.colors['neon_red']))
                else:
                    self.message_queue.put(("log", "✅ NO CRITICAL VULNERABILITIES FOUND", self.colors['neon_green']))
                
                self.message_queue.put(("stats", round_num-1, 0, len(set(all_cves)), "COMPLETED"))
                
        except Exception as e:
            self.message_queue.put(("log", f"💀 SCAN ERROR: {e}", self.colors['neon_red']))
        finally:
            self.message_queue.put(("scan_complete", None))
            
    def process_messages(self):
        """Process messages from the scan thread"""
        try:
            while True:
                msg_type, *args = self.message_queue.get_nowait()
                
                if msg_type == "log":
                    message, color = args[0], args[1] if len(args) > 1 else None
                    self.log_message(message, color)
                elif msg_type == "stats":
                    self.update_stats(*args)
                elif msg_type == "scan_complete":
                    self.scanning = False
                    self.start_button.configure(state=tk.NORMAL)
                    self.stop_button.configure(state=tk.DISABLED)
                    self.progress.stop()
                    break
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_messages)
        
    def run(self):
        """Start the GUI application"""
        # Configure ttk styles for cyberpunk theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main progress bar
        style.configure(
            'Cyberpunk.Horizontal.TProgressbar',
            background=self.colors['neon_cyan'],
            troughcolor=self.colors['bg_tertiary'],
            borderwidth=0,
            lightcolor=self.colors['neon_cyan'],
            darkcolor=self.colors['neon_cyan']
        )
        
        # CPU progress bar
        style.configure(
            'CPU.Horizontal.TProgressbar',
            background=self.colors['neon_green'],
            troughcolor=self.colors['bg_tertiary'],
            borderwidth=0,
            lightcolor=self.colors['neon_green'],
            darkcolor=self.colors['neon_green']
        )
        
        # RAM progress bar
        style.configure(
            'RAM.Horizontal.TProgressbar',
            background=self.colors['neon_pink'],
            troughcolor=self.colors['bg_tertiary'],
            borderwidth=0,
            lightcolor=self.colors['neon_pink'],
            darkcolor=self.colors['neon_pink']
        )
        
        self.root.mainloop()

# ========== 12. Main Function ==========
def main():
    """Launch the Cyberpunk GUI"""
    app = CyberpunkPentestGUI()
    app.run()

if __name__ == "__main__":
    main()
