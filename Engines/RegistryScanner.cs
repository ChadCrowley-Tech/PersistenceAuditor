using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace PersistenceAuditor.Engines
{
    /// <summary>
    /// Actively hunts for persistence mechanisms hidden in Windows Registry startup locations.
    /// </summary>
    public static class RegistryScanner
    {
        public static List<ThreatArtifact> ScanRunKeys()
        {
            List<ThreatArtifact> artifacts = new List<ThreatArtifact>();

            // Critical paths where malware establishes persistence
            var targetLocations = new Dictionary<string, RegistryKey>
            {
                { @"HKLM\Run", Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") },
                { @"HKLM\RunOnce", Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce") },
                { @"HKCU\Run", Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") },
                { @"HKCU\RunOnce", Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce") }
            };

            foreach (var location in targetLocations)
            {
                if (location.Value != null)
                {
                    using (RegistryKey key = location.Value)
                    {
                        foreach (string valueName in key.GetValueNames())
                        {
                            string targetPath = key.GetValue(valueName)?.ToString() ?? "UNKNOWN";

                            artifacts.Add(new ThreatArtifact
                            {
                                Category = $"Run Key ({location.Key})",
                                Name = valueName,
                                Path = targetPath,
                                Severity = HeuristicEngine.EvaluateSeverity(targetPath, valueName),
                                Status = "Active"
                            });
                        }
                    }
                }
            }

            return artifacts;
        }       
    }
}
