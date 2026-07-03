using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PersistenceAuditor.Engines
{
    /// <summary>
    /// MITRE ATT&CK T1053.005: Identifies persistence mechanisms established via Windows Scheduled Tasks
    /// </summary>
    public static class ScheduledTaskScanner
    {
        public static List<ThreatArtifact> ScanTasks()
        {
            List<ThreatArtifact> artifacts = new List<ThreatArtifact>();

            // Query the host via PowerShell to enumerate active scheduled tasks and isolate execution actions
            string psCommand = "Get-ScheduledTask | Where-Object State -ne 'Disabled' | ForEach-Object { $_.TaskName + '|||' + $_.Actions[0].Execute }";

            ProcessStartInfo processInfo = new ProcessStartInfo()
            {
                FileName = "powershell",
                Arguments = $"-NoProfile -Command \"{psCommand}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            try
            {
                using (Process process = Process.Start(processInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    string[] lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

                    foreach (string line in lines)
                    {
                        string[] parts = line.Split(new[] { "|||" }, StringSplitOptions.None);

                        if (parts.Length == 2)
                        {
                            string taskName = parts[0].Trim();
                            string executionPath = parts[1].Trim();

                            // Exclude null payloads and native Component Object Model (COM) handler actions to isolate non-standard behaviors
                            if (!string.IsNullOrEmpty(executionPath) && !executionPath.Contains("ComHandler"))
                            {
                                artifacts.Add(new ThreatArtifact
                                {
                                    Category = "Scheduled Task",
                                    Name = taskName,
                                    Path = executionPath,
                                    Severity = HeuristicEngine.EvaluateSeverity(executionPath, taskName),
                                    Status = "Active"
                                });
                            }
                        }
                    }
                }
            }
            catch 
            {
                // Fail silently to ensure localized security context blocks do not disrupt the broader pipeline execution
            }

            return artifacts;
        }        
    }
}
