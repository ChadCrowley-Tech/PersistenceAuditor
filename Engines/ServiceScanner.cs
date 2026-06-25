using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PersistenceAuditor.Engines
{
    /// <summary>
    /// MITRE ATT&CK T1543.003: Hunts for persistence hidden in Windows Services.
    /// </summary>
    public static class ServiceScanner
    {
        public static List<ThreatArtifact> ScanServices()
        {
            List<ThreatArtifact> artifacts = new List<ThreatArtifact>();

            // Query WMI for active services and extract their execution paths
            string psCommand = "Get-CimInstance Win32_Service | Where-Object StartMode -ne 'Disabled' | ForEach-Object { $_.Name + '|||' + $_.PathName }";

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
                            string serviceName = parts[0].Trim();
                            string executionPath = parts[1].Trim();

                            // Filter out blank paths and the massive flood of generic svchost.exe processes
                            if (!string.IsNullOrEmpty(executionPath) && !executionPath.Contains("svchost.exe"))
                            {
                                artifacts.Add(new ThreatArtifact
                                {
                                    Category = "Windows Service",
                                    Name = serviceName,
                                    Path = executionPath,
                                    Severity = HeuristicEngine.EvaluateSeverity(executionPath, serviceName),
                                    Status = "Active"
                                });
                            }
                        }
                    }
                }
            }
            catch { }

            return artifacts;
        }
    }
}
