using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PersistenceAuditor.Engines
{
    /// <summary>
    /// MITRE ATT&CK T1053.005: Hunts for persistence hidden in Windows Scheduled Tasks.
    /// </summary>
    public static class ScheduledTaskScanner
    {
        public static List<ThreatArtifact> ScanTasks()
        {
            List<ThreatArtifact> artifacts = new List<ThreatArtifact>();

            // Ask PowerShell to get all active tasks, and grab the Task Name and the actual Execution Path
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

                            // Filter out empty executions or purely native COM handlers to reduce noise
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
            catch { /* Silently handle access denied errors for system-level tasks */ }

            return artifacts;
        }        
    }
}
