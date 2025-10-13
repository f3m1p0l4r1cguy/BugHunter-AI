# 🚀 QUICK START GUIDE

## Installation (2 minutes)

### Step 1: Install Dependencies
```bash
python install_dependencies.py
```

### Step 2: Verify Installation
You should see:
```
✅ ALL DEPENDENCIES INSTALLED SUCCESSFULLY!
🚀 You can now run: python3 AIlinuxV2.py
```

## Running the Tool (30 seconds)

### Launch
```bash
python AIlinuxV2.py
```

### First Time Setup

1. **Configure Settings** (left panel):
   - Max Concurrent Tools: Select **2** (recommended)
   - CPU Threshold: Keep at **70%**
   - RAM Threshold: Keep at **75%**

2. **Enter Target**:
   - Type target IP or domain (e.g., `192.168.1.1` or `example.com`)

3. **Select Tools** (optional):
   - Default selection is fine for first run
   - Or uncheck tools you don't want to run

4. **Start Scan**:
   - Click **"▶ INITIATE SCAN"**

## What You'll See

### Top Section
```
🚀 CYBERPUNK AI PENTEST AGENT 2077 🚀
SYSTEM READY • NEURAL NETWORK ONLINE • AWAITING TARGET
```

### Left Panel
- Target input field
- Control buttons (Start/Stop/Export)
- Settings sliders
- Tool selection checkboxes

### Right Panel - Top
```
🖥️ SYSTEM RESOURCES
CPU: 45.2% [▓▓▓▓▓░░░░░]
RAM: 62.8% [▓▓▓▓▓▓░░░░]
```

### Right Panel - Middle
```
📋 TOOL EXECUTION QUEUE
⚡ RUNNING:
  • nmap (45s)
  • nikto (23s)

📋 QUEUED:
  • sqlmap
  • wpscan
  ... and 3 more

✅ COMPLETED: 5
❌ FAILED: 0
```

### Right Panel - Bottom
```
📱 NEURAL CONSOLE OUTPUT
[14:23:45] 🚀 CYBERPUNK AI PENTEST AGENT INITIALIZED
[14:23:46] 🎯 TARGET ACQUIRED: example.com
[14:23:47] ⚡ LAUNCHING: nmap
[14:23:48] ⚡ LAUNCHING: nikto
[14:24:32] ✅ COMPLETED nmap
...
```

## Understanding the Interface

### Resource Meters
- **Green**: Healthy (< 80% of threshold)
- **Yellow**: Caution (80-100% of threshold)
- **Red**: At capacity (> threshold)

### Tool Status Icons
- ⏳ **PENDING**: Not yet queued
- 📋 **QUEUED**: Waiting for resources
- ⚡ **RUNNING**: Currently executing
- ✅ **COMPLETED**: Successfully finished
- ❌ **FAILED**: Execution failed

### Console Colors
- 🔵 **Cyan**: System information
- 💚 **Green**: Success messages
- 💛 **Yellow**: Running/warning
- 💗 **Pink**: Round/phase info
- ❤️ **Red**: Errors/critical findings

## Common Scenarios

### Scenario 1: Fast System, Many Tools
```
Settings:
✓ Max Concurrent: 3
✓ CPU Threshold: 80%
✓ RAM Threshold: 85%

Result: Faster scans, tools complete quickly
```

### Scenario 2: Slow System, Few Tools
```
Settings:
✓ Max Concurrent: 1
✓ CPU Threshold: 60%
✓ RAM Threshold: 65%

Result: Slower but stable, system remains responsive
```

### Scenario 3: Balanced (Recommended)
```
Settings:
✓ Max Concurrent: 2
✓ CPU Threshold: 70%
✓ RAM Threshold: 75%

Result: Good balance of speed and stability
```

## Tips for Best Results

### ✅ DO:
- Start with default settings
- Monitor resource meters
- Wait for each round to complete
- Review the console output
- Export logs when done

### ❌ DON'T:
- Set thresholds too high (>85%)
- Run 3+ tools on low-end systems
- Close terminal windows that open
- Interrupt scans unnecessarily
- Scan unauthorized targets

## Stopping a Scan

1. Click **"⏹ TERMINATE"** button
2. Wait for current tools to finish (few seconds)
3. Check console for confirmation:
   ```
   [14:30:15] ⚠ SCAN TERMINATED BY USER
   ```

## Exporting Results

1. Click **"💾 EXPORT LOGS"** button
2. Choose save location
3. Give it a name (e.g., `scan_example_com.json`)
4. Click **Save**

The exported file contains:
- All scan rounds
- Tools used
- CVEs discovered
- Timestamps
- Tool execution statistics

## Interpreting Results

### In the Console
Look for:
- `🚨 CVEs DISCOVERED`: Security vulnerabilities found
- `✅ COMPLETED`: Tools that finished successfully
- `❌ FAILED`: Tools that encountered errors
- `🤖 AI RESPONSE`: AI analysis and recommendations

### In the Export File
Open with any text editor to see:
```json
{
  "session_id": "20241013_142345_a1b2",
  "target": "example.com",
  "rounds": [
    {
      "round": 1,
      "tools": ["nmap", "nikto", "sqlmap"],
      "cves": ["CVE-2021-1234"],
      "completed": 3,
      "failed": 0
    }
  ],
  "completed_at": "2024-10-13T14:45:23"
}
```

## Troubleshooting

### Problem: Nothing happens when I click Start
**Solution**: Make sure you entered a target

### Problem: Tools immediately show as FAILED
**Solution**: Tools may not be installed on your system

### Problem: CPU/RAM always red
**Solution**: Lower the thresholds or reduce max concurrent tools

### Problem: Queue not progressing
**Solution**: System at capacity, wait or adjust settings

### Problem: Application won't start
**Solution**: Run `install_dependencies.py` first

## Next Steps

1. **Read the full README**: `CYBERPUNK_PENTEST_README.md`
2. **Understand optimizations**: `OPTIMIZATION_SUMMARY.md`
3. **Configure API keys**: Edit the `API_KEYS` list in the code
4. **Install security tools**: nmap, nikto, sqlmap, etc.
5. **Practice on test systems**: Use your own VMs or lab environments

## Legal Notice

⚠️ **IMPORTANT**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

This tool is for:
- ✅ Your own systems
- ✅ Systems you have permission to test
- ✅ Lab/training environments
- ✅ Bug bounty programs (follow their rules)

NOT for:
- ❌ Unauthorized systems
- ❌ Production systems without approval
- ❌ Any illegal activity

## Support

If you encounter issues:
1. Check the console output for error messages
2. Review the `errors.log` file in the scan directory
3. Verify all security tools are installed
4. Check system requirements
5. Ensure Python 3.7+ is installed

## Enjoy!

You're now ready to use the Cyberpunk AI Pentest Agent! Remember to:
- Use responsibly and legally
- Start with conservative settings
- Monitor resource usage
- Learn from the results

Happy (authorized) hacking! 🎯🔐
