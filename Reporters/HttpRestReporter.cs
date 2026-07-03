using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using PersistenceAuditor.Interfaces;

namespace PersistenceAuditor.Reporters
{
    /// <summary>
    /// Handles outbound transmission of incident telemetry to a remote REST API endpoint.
    /// </summary>
    public class HttpRestReporter : IIncidentReporter
    {
        // Reuses a single HttpClient instance per Microsoft best practices to prevent socket exhaustion
        private static readonly HttpClient _httpClient = new HttpClient();
        private readonly string _endpointUrl;

        public HttpRestReporter(string endpointUrl)
        {
            _endpointUrl = endpointUrl;
        }

        public async Task<bool> ReportIncidentAsync(ThreatArtifact artifact)
        {
            // Enforces a fallback safety mechanism if the endpoint is not properly configured
            if (string.IsNullOrWhiteSpace(_endpointUrl) || _endpointUrl.Contains("placeholder"))
            {
                return false;
            }

            try
            {
                var payload = new
                {
                    Source = "PersistenceAuditor",
                    GeneratedTime = DateTime.UtcNow,
                    TargetHost = Environment.MachineName,
                    AlertData = artifact
                };

                string jsonPayload = JsonSerializer.Serialize(payload);
                var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                // Execute outbound network request
                HttpResponseMessage response = await _httpClient.PostAsync(_endpointUrl, content);

                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
