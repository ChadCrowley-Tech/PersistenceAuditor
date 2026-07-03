using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace PersistenceAuditor.Engines
{
    /// <summary>
    /// MITRE ATT&CK T1547.001: Enumerates standard Windows Registry execution blocks to identify auto-run persistence mechanisms
    /// </summary>
    public static class RegistryScanner
    {
        public static List<ThreatArtifact> ScanRunKeys()
        {
            List<ThreatArtifact> artifacts = new List<ThreatArtifact>();

            // Target registry hive paths historically utilized for run and run-once execution persistence
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
