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

### Feature Highlights
| <img src="Images/PersistenceAuditorScreenshot.png" width="250"> | <img src="Images/PersistenceAuditor17.png" width="250"> | <img src="Images/PersistenceAuditor18.png" width="250"> | <img src="Images/PersistenceAuditor1.png" width="250"> |
| :---: | :---: | :---: | :---: |
| **Starting 'SplashScreen'** | **Main Dashboard** | **Program Scanning** | **Initial Scan Results** |
<details>
<summary><b>🖱️ Click to expand full Application Gallery (18 Additional Images)</b></summary>
<br>
  
| <img src="Images/PersistenceAuditor2.png" width="250"> | <img src="Images/PersistenceAuditor4.png" width="250"> | <img src="Images/PersistenceAuditor20.png" width="250"> | <img src="Images/PersistenceAuditor21.png" width="250"> |
| :---: | :---: | :---: | :---: |
| **[Severity - 'Critical']** | **[Local Audit (.json)]** | **[Local Audit: IncidentAuditTrail.json file]** | **[Local Audit creates daily .json logs]** |
  
| <img src="Images/PersistenceAuditor22.png" width="250"> | <img src="Images/PersistenceAuditor23.png" width="250"> | <img src="Images/PersistenceAuditor24.png" width="250"> | <img src="Images/PersistenceAuditor25.png" width="250"> |
| :---: | :---: | :---: | :---: |
| **[API Mode - Dispatch Threat]** | **[Input API endpoint (Using Webhook.com for testing)]** | **[Verification of successful API Dispatch]** | **[Webhook.com site showing it recieved dispatched threat]** |

| <img src="Images/PersistenceAuditor6.png" width="250"> | <img src="Images/PersistenceAuditor7.png" width="250"> | <img src="Images/PersistenceAuditor8.png" width="250"> | <img src="Images/PersistenceAuditor9.png" width="250"> |
| :---: | :---: | :---: | :---: |
| **[Search menu selection results for 'program']** | **[Verification of Scheduled Task deletion]** | **[Verification of successful Scheduled Task deletion]** | **[Verification of Run Key (HKLM\Run) deletion]** |

| <img src="Images/PersistenceAuditor10.png" width="250"> | <img src="Images/PersistenceAuditor11.png" width="250"> | <img src="Images/PersistenceAuditor12.png" width="250"> | <img src="Images/PersistenceAuditor13.png" width="250"> |
| :---: | :---: | :---: | :---: |
| **[Verification of successful Run Key (HKLM\Run) deletion]** | **[Verification of Windows Service deletion]** | **[All Critical threats have been deleted]** | **[Severity level - Suspicious threats]** |

| <img src="Images/PersistenceAuditor14.png" width="250"> | <img src="Images/PersistenceAuditor15.png" width="250"> | <img src="Images/PersistenceAuditor16.png" width="250"> | <img src="Images/PersistenceAuditor19.png" width="250"> |
| :---: | :---: | :---: | :---: |
| **[Verification of Run Key (HKLM\Run) deletion]** | **[Verification of Scheduled Task deletion]** | **[All Suspicious threats have been deleted]** | **[Export to Clipboard option]** |
</details>
