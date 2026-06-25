# PersistenceAuditor 

**PersistenceAuditor** is a dedicated, WPF-based threat hunting and SIEM dashboard designed to identify and neutralize Windows persistence mechanisms. 
* Engineered in C#, the tool conducts live static scanning across Registry Run Keys, Scheduled Tasks, and unverified Windows Services (MITRE T1543.003).
* By routing telemetry through a centralized HeuristicEngine, the application dynamically grades threat severity and filters safe paths to minimize alert fatigue.
* Features an elevated PowerShell remediation payload for active threat purging and an export-to-clipboard function to streamline incident ticketing, significantly reducing manual investigation time.
