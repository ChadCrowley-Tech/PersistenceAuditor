using System;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using PersistenceAuditor.Interfaces;

namespace PersistenceAuditor.Reporters
{
    /// <summary>
    /// Handles localized persistence of incident telemetry using flat-file JSON storage with daily log rotation.
    /// </summary>
    public class LocalJsonReporter : IIncidentReporter
    {
        /// <summary>
        /// Dynamically generates the file path, appending the current UTC date to enforce daily log rotation.
        /// </summary>
        private string GetActiveLogFilePath()
        {
            string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string dateSuffix = DateTime.UtcNow.ToString("yyyy-MM-dd");
            return Path.Combine(baseDir, $"IncidentAuditTrail_{dateSuffix}.json");
        }

        public async Task<bool> ReportIncidentAsync(ThreatArtifact artifact)
        {
            try
            {
                var incidentPayload = new
                {
                    IncidentId = Guid.NewGuid().ToString(),
                    // Formats the timestamp strictly to ISO 8601 standards
                    Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    HostName = Environment.MachineName,
                    Details = artifact
                };

                string jsonString = JsonSerializer.Serialize(incidentPayload, new JsonSerializerOptions { WriteIndented = true });
                string targetFile = GetActiveLogFilePath();

                // Appends the payload to the daily log file, creating a new file if it does not currently exist
                await Task.Run(() => File.AppendAllText(targetFile, jsonString + Environment.NewLine + "---" + Environment.NewLine));
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
