using System;
using System.Collections.Generic;

namespace PersistenceAuditor.Engines
{
    /// <summary>
    /// Centralized analysis engine to grade threat severity and reduce Alert Fatigue via Dynamic Whitelisting.
    /// </summary>
    public static class HeuristicEngine
    {
        // The Dynamic Executable Whitelist
        // Adding known safe Electron/App-based applications that normally flag as critical
        private static readonly HashSet<string> SafeExecutables = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "onedrive.exe",
            "teams.exe",
            "ms-teams.exe",
            "discord.exe",
            "skype.exe",
            "msedge.exe",
            "securityhealthsystray.exe"
        };

        // The Dynamic Path Whitelist
        // Accounts for Windows environmental variables to stop false positives
        private static readonly List<string> SafePaths = new List<string>
        {
            @"c:\windows\",
            @"c:\program files\",
            @"c:\program files (x86)\",
            @"%windir%\system32",
            @"%systemroot%\system32"
        };

        public static string EvaluateSeverity(string path, string name)
        {
            if (string.IsNullOrWhiteSpace(path)) return "SUSPICIOUS";

            string lowerPath = path.ToLower();
            string lowerName = name.ToLower();

            // Check Executable Whitelist first (Overrides the AppData threat logic)
            foreach (string safeExe in SafeExecutables)
            {
                if (lowerPath.Contains(safeExe) || lowerName.Contains(safeExe))
                {
                    return "BASELINE";
                }
            }

            // Check Path Whitelist
            foreach (string safePath in SafePaths)
            {
                if (lowerPath.Contains(safePath))
                {
                    return "BASELINE";
                }
            }

            // Identify Malicious Indicators (If it made it past the whitelist, it's highly dangerous)
            if (lowerPath.Contains(@"\appdata\") || lowerPath.Contains(@"\temp\") ||
                lowerPath.Contains("powershell.exe") || lowerPath.Contains("cmd.exe"))
            {
                return "CRITICAL";
            }

            // Default Catch-All for unknown paths
            return "SUSPICIOUS";
        }
    }
}