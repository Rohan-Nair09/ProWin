# ProWin — Windows Service & Process Monitoring Agent

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows)

**A real-time endpoint security monitoring dashboard for Windows.**  
Detects suspicious processes, audits services, maps process hierarchies,  
and alerts on persistence mechanisms — all from a single GUI.

</div>

---

## 📸 Features at a Glance

| Tab | What It Shows |
|---|---|
| ⚙ **Processes** | All running processes — PID, path, CPU, memory, severity |
| 🔧 **Services** | All Windows services with tamper/misconfiguration detection |
| 🚨 **Findings** | Security alerts filtered by CRITICAL / HIGH / MEDIUM / LOW |
| 📌 **Startup Apps** | Registry Run keys, startup folders, scheduled tasks |
| 📊 **Statistics** | Bar + pie charts of finding distribution |
| 🌲 **Process Map** | NetworkX graph of parent→child process relationships |

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/Rohan-Nair09/ProWin.git
cd ProWin
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure your settings
```bash
# Copy the example config to create your local settings file
copy config\settings.example.json config\settings.json
```
Then open `config/settings.json` and add your VirusTotal API key:
```json
"virustotal_api_key": "YOUR_API_KEY_HERE"
```
> ⚠️ `config/settings.json` is in `.gitignore` — your API key will **never** be uploaded to GitHub.  
> Get a free API key at [virustotal.com](https://www.virustotal.com)

### 4. Run the app
```bash
# For full coverage (WMI, process owners, signatures)
# Right-click → Run as Administrator, then:
python main.py

# Works without admin too (limited WMI access)
python main.py
```

---

## 🛡️ What It Detects

### Process-level threats
- ✅ **Known malware names** — matched against a curated catalogue of 40+ threat executables (RATs, ransomware, miners, credential dumpers)
- ✅ **Suspicious spawn chains** — 30+ parent→child rules (e.g. `winword.exe → powershell.exe` = Office macro attack)
- ✅ **Process hollowing indicators** — user-space processes with no backing executable on disk
- ✅ **Duplicate singleton processes** — two `lsass.exe` instances = masquerading/injection
- ✅ **High CPU processes** — configurable threshold (default 80%), flags potential crypto-miners
- ✅ **Risky directory execution** — processes launched from `\Temp\`, `\Downloads\`, `\Desktop\`

### Service-level threats
- ✅ **Unquoted service paths** — privilege escalation vulnerability
- ✅ **Services in temp directories** — malware persistence via service installation
- ✅ **Critical security services stopped** — Defender, Firewall, Event Log tampered

### Persistence mechanisms
- ✅ **HKCU/HKLM Run & RunOnce registry keys** — all 5 key paths
- ✅ **Shell startup folders** — user + all-users
- ✅ **Windows Scheduled Tasks** — via `schtasks.exe` with SYSTEM-account detection

---

## 📁 Project Structure

```
ProWin/
├── main.py                        # Entry point — ScanOrchestrator + GUI launch
├── requirements.txt               # Python dependencies
├── config/
│   └── settings.json              # Configuration (interval, thresholds, API key)
├── database/
│   └── db_manager.py              # SQLite persistence (WAL mode)
├── detection/
│   ├── blacklist.py               # KNOWN_THREATS catalogue
│   ├── whitelist.py               # TRUSTED_PROCS + CPU_IGNORE_LIST
│   └── rules_engine.py            # PROC_SPAWN_RULES + assess_process/service
├── monitor/
│   ├── process_monitor.py         # collect_running_processes()
│   ├── service_monitor.py         # collect_system_services()
│   ├── startup_monitor.py         # scan_startup_locations()
│   ├── anomaly_detector.py        # run_anomaly_sweep()
│   ├── parent_child_analyzer.py   # construct_proc_hierarchy()
│   └── persistence_detector.py    # enumerate_persistence_vectors()
├── gui/
│   ├── dashboard.py               # ProWinApp — 6-tab Tkinter window
│   ├── alerts.py                  # dispatch_finding() + tally_by_level()
│   └── statistics.py              # build_bar_chart / pie / process_graph
└── utils/
    ├── helpers.py                  # humanize_size, level_to_hex, load_config
    ├── logger.py                   # MultiSinkLogger (TXT + CSV + JSONL)
    ├── report_generator.py         # build_pdf/txt/json_report + export_all
    ├── signature_checker.py        # verify_executable_signature (WinVerifyTrust)
    └── virustotal.py               # query_hash_reputation (VT API v3)
```

---

## 📄 Report Export

Click **Export Report** in the GUI to generate three files in `reports/`:

| Format | Use Case |
|---|---|
| **PDF** | Formatted A4 report with colour-coded tables (ReportLab) |
| **TXT** | Plain-text summary — shareable, pasteable |
| **JSON** | Machine-readable full dump for SIEM ingestion |

---

## ⚙️ Configuration (`config/settings.json`)

| Key | Default | Description |
|---|---|---|
| `refresh_interval_sec` | `10` | Seconds between auto-refresh scans |
| `cpu_alert_threshold` | `80.0` | CPU % above which a finding is raised |
| `virustotal_api_key` | `""` | Your VT API key (free at virustotal.com) |
| `database_path` | `database/monitoring.db` | SQLite database location |
| `reports_path` | `reports/` | Output folder for exported reports |
| `logs_path` | `logs/` | Log file directory |
| `max_log_size_mb` | `10` | Max size before log rotation |

---

## 🔧 Tech Stack

| Library | Purpose |
|---|---|
| `psutil` | Live process enumeration |
| `wmi` | Windows service queries via WMI |
| `winreg` | Registry key reading |
| `tkinter` | GUI framework |
| `matplotlib` | Embedded charts (Agg backend) |
| `networkx` | Process relationship graph |
| `sqlite3` | Local database (built-in) |
| `reportlab` | PDF generation |
| `requests` | VirusTotal API v3 calls |
| `ctypes` | WinVerifyTrust Authenticode check |

---

## 📋 Requirements

- **Python 3.10+**
- **Windows 10 / 11**
- **Administrator privileges** recommended (for full WMI and signature coverage)

Install all dependencies:
```bash
pip install -r requirements.txt
```

---

## 📝 Logging

Every scan event is written to three simultaneous sinks:

| File | Format | Purpose |
|---|---|---|
| `logs/prowin.log` | Plain text (rotating) | Human-readable audit trail |
| `logs/audit.csv` | CSV | Import into Excel / SIEM |
| `logs/audit.jsonl` | Newline-delimited JSON | Automated ingestion |

---

## ⚠️ Disclaimer

ProWin is built for **educational and internship purposes**. It is a monitoring and alerting tool — it does not remove, quarantine, or modify any processes or files on your system.

---

## 👨‍💻 Developed By:

**Rohan Nair**  
 

---

## 📜 License

MIT License — free to use, modify, and distribute with attribution.
