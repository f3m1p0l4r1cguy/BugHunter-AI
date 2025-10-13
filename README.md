# 🚀 BUGHUNTER AI PENTEST AGENT

![Logo](https://github.com/ARESHAmohanad/BugHunter-AI/blob/main/IMG_20251013_144744_076.jpg?raw=true)

**Automated penetration testing agent with a cyber-inspired GUI, resource-aware task scheduling, and AI-assisted analysis.**

---

## 🔎 Short description
Automation tool for penetration testing with a GUI, resource-aware task queueing, and AI-assisted analysis. Designed for labs and authorized testing only.

---

## ⚠️ Security / Legal Notice
**Use only on systems you own or have explicit permission to test.** Unauthorized scanning is illegal. This script can run intrusive tools and may send reports to an external API (configurable). Review the code and API keys before running.

---

## 🧰 Key Features
- Resource-aware task queueing (CPU / RAM) with configurable limits.  
- Tool resource profiles (estimated CPU/RAM/time consumption).  
- GUI built with **tkinter** featuring a "cyberpunk" theme (resource monitor, queue, console).  
- Integration with an AI service to analyze reports and suggest commands/actions.  
- Per-round report generation and automated CVE extraction.

---

## 📦 Requirements
- Python 3.7+ (3.9+ recommended)  
- `psutil`, `requests`, and `tkinter` (see `install_dependencies.py`).  
- Optional external pentesting tools for full functionality: `nmap`, `sqlmap`, `nikto`, `nuclei`, `masscan`, `hydra`, `metasploit`, etc. Install via your distro package manager.

---

## 🚀 Quick Installation

1. Clone the repository:
```bash
git clone https://github.com/ARESHAmohanad/BugHunter-AI
cd BugHunter-AI
```

2. Install Python dependencies (included script):
```bash
python3 install_dependencies.py
```
(This script checks and installs `psutil` and `requests`. `tkinter` may need to be installed via system packages.)

3. (Optional) Install system pentest tools:
```bash
# Example on Debian/Ubuntu
sudo apt update
sudo apt install -y nmap sqlmap nikto masscan
```

---

## ▶️ Quick start (run)
See `QUICK_START.md` for a visual walkthrough or run:
```bash
python3 AIlinuxV2.py
```
Enter the target (authorized targets only), adjust `Max Concurrent Tools`, CPU/RAM thresholds, and click **INITIATE SCAN** in the GUI.

---

## ⚙️ Important Configuration
- Configure API keys (if using AI integration) at the top of `AIlinuxV2.py`: `API_KEYS` and `API_URL`. The integration can send reports to an external endpoint — review privacy implications before sending sensitive data.  
- Adjust `Max Concurrent Tools`, `CPU Threshold`, and `RAM Threshold` in the GUI to avoid overloading your host.

---

## 🗂️ Output structure (example)
Each session produces a directory `AI_Pentest_YYYYMMDD_HHMMSS_<id>/` with per-round subfolders:
```
AI_Pentest_YYYYMMDD_HHMMSS_ID/
├─ round_1/
│  ├─ nmap.txt
│  ├─ nikto.txt
│  ├─ report.json
│  └─ decision.json
├─ round_2/
├─ errors.log
└─ final_report.json
```
Reports and decisions are used by the AI engine to determine next steps.

---

## 🛠️ How it works (technical summary)
1. User starts a scan and enqueues tools.  
2. `ResourceMonitor` checks CPU/RAM and permits execution only when safe.  
3. `ToolQueueManager` manages concurrent execution (configurable).  
4. Outputs are aggregated into `report.json`.  
5. The aggregated results are optionally sent to the AI engine; the AI returns commands inside `<COMMANDS>` and a `<DECISION>` JSON that lists next tools.

---

## 📚 Documentation
- `QUICK_START.md` — quick walkthrough and examples.  
- `OPTIMIZATION_SUMMARY.md` — summary of resource-usage optimizations (queueing, profiles, monitor).

---

## 🤝 Contributing
Contributions welcome. Ideas:
- Add new tool resource profiles
- Improve AI response validation and command sanitization
- Add Docker/container support for isolated execution

---

## 🧾 License
For educational use / authorized testing. Add a license file (MIT, Apache-2.0, etc.) as desired.

---

**NOTE:** Review the code before running in any production environment. For safe usage, run inside an isolated VM against authorized labs or CTFs.
