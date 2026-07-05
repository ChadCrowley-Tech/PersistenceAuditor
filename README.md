# PersistenceAuditor

**PersistenceAuditor** is a dedicated, WPF-based threat hunting and SIEM telemetry dashboard designed to identify, classify, and neutralize Windows persistence mechanisms. 

Engineered in C# (.NET), the tool bridges the gap between endpoint forensics and enterprise Security Operations Centers (SOC). It conducts live static scanning across critical operating system hives and routes the telemetry through a decoupled architecture, allowing analysts to rapidly purge active threats or dispatch JSON-structured payloads to remote endpoints.

## 🎯 Core Features

### Advanced Threat Telemetry
* **Live Artifact Scanning:** Actively enumerates Registry Run Keys, Scheduled Tasks, and unverified Windows Services.
* **Dynamic Heuristic Engine:** Grades threat severity (CRITICAL, SUSPICIOUS, BASELINE) via a centralized analysis class to heavily reduce SOC alert fatigue.
* **Configuration Hot-Swapping:** Utilizes a `WhitelistConfig.json` file for dynamic path and executable safe-listing. Changes are parsed and applied in real-time during scans without requiring process restarts.

### Enterprise Routing Architecture
* **Interface-Driven Design:** Implements an `IIncidentReporter` contract to seamlessly decouple the detection engine from the transmission pipeline.
* **API Dispatch Mode:** Wraps metadata into structured, ISO 8601 UTC-stamped JSON payloads and dispatches them to external SIEM/SOAR Webhooks via an asynchronous `HttpClient`.
* **Local Audit Mode:** Provides a localized flat-file JSON storage fallback featuring daily log rotation for disconnected forensic analysis.

### Active Remediation & UI
* **Elevated PowerShell Execution:** Bypasses native CLI quote restrictions by dynamically building WMI and PowerShell payloads, executing them securely via UAC-prompted background processes.
* **Cyberpunk WPF Interface:** Features a custom, control-templated dark theme, completely decoupled from the C# logic via centralized `App.xaml` resource dictionaries.
* **Real-Time Filtering:** Leverages `ICollectionView` for instantaneous UI search and severity filtering without querying the backend dataset.

## 🛡️ MITRE ATT&CK Mapping
This tool specifically hunts for behaviors aligned with the following enterprise matrix techniques:
* **T1547.001:** Boot or Logon Autostart Execution: Registry Run Keys
* **T1053.005:** Scheduled Task/Job: Scheduled Task
* **T1543.003:** Create or Modify System Process: Windows Service

## 📸 Interface Preview
(Screenshots coming soon...)
