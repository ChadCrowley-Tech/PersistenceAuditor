using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace PersistenceAuditor.Engines
{
    // Data model for deserializing the JSON configuration payload
    public class WhitelistConfig
    {
        public List<string> SafeExecutables { get; set; } = new List<string>();
        public List<string> SafePaths { get; set; } = new List<string>();
    }

    /// <summary>
    /// Centralized analysis engine to grade threat severity and reduce alert fatigue via dynamic whitelisting
    /// </summary>
    public static class HeuristicEngine
    {
        private static HashSet<string> SafeExecutables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static List<string> SafePaths = new List<string>();
        private static readonly string ConfigFile = "WhitelistConfig.json";



        // Public method accessible by the presentation layer to trigger dynamic configuration reloads
        public static void ReloadConfiguration()
        {
            try
            {
                if (File.Exists(ConfigFile))
                {
                    string json = File.ReadAllText(ConfigFile);
                    var config = JsonSerializer.Deserialize<WhitelistConfig>(json);

                    if (config != null)
                    {
                        // Clear existing collections from memory prior to reloading the updated configuration
                        SafeExecutables.Clear();
                        SafePaths.Clear();

                        foreach (var exe in config.SafeExecutables)
                        {
                            SafeExecutables.Add(exe);
                        }

                        foreach (var path in config.SafePaths)
                        {
                            SafePaths.Add(Environment.ExpandEnvironmentVariables(path).ToLower());
                        }
                    }
                }
            }
            catch 
            {
                // Fail silently to ensure a missing or malformed configuration file does not halt application execution; defaults to strict gradin
            }
        }

        public static string EvaluateSeverity(string path, string name)
        {
            if (string.IsNullOrWhiteSpace(path)) return "SUSPICIOUS";

            // Expand environment variables prior to executing string comparison to ensure accurate path evaluation
            string expandedPath = Environment.ExpandEnvironmentVariables(path).ToLower();
            string lowerName = name.ToLower();

            // Evaluate the executable whitelist first (Overrides directory-based threat logic)
            foreach (string safeExe in SafeExecutables)
            {
                if (expandedPath.Contains(safeExe) || lowerName.Contains(safeExe))
                {
                    return "BASELINE";
                }
            }

            // Evaluate the directory path whitelist
            foreach (string safePath in SafePaths)
            {
                if (expandedPath.Contains(safePath))
                {
                    return "BASELINE";
                }
            }

            // Identify malicious indicators (Artifacts bypassing the whitelist are classified as critical)
            if (expandedPath.Contains(@"\appdata\") || expandedPath.Contains(@"\temp\") ||
                expandedPath.Contains("powershell.exe") || expandedPath.Contains("cmd.exe"))
            {
                return "CRITICAL";
            }

            // Default fallback for unknown paths
            return "SUSPICIOUS";
        }
    }
}