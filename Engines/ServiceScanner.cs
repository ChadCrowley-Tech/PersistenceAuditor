using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PersistenceAuditor.Engines
{
    /// <summary>
    /// MITRE ATT&CK T1543.003: Identifies persistence mechanisms established via Windows Services.
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

                            // Exclude empty paths and native Service Host (svchost.exe) allocations to reduce baseline noise
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
            catch 
            {
                // Fail silently to ensure localized WMI permission errors do not crash the background scanning thread
            }

            return artifacts;
        }
    }
}
