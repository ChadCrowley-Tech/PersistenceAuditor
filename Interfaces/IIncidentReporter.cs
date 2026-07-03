using System.Threading.Tasks;

namespace PersistenceAuditor.Interfaces
{
    /// <summary>
    /// Standardized contract for dispatching security incident telemetry.
    /// </summary>
    public interface IIncidentReporter
    {
        /// <summary>
        /// Dispatches a detected threat artifact to the designated ticketing or logging destination.
        /// </summary>
        /// <param name="artifact">The threat telemetry metadata payload.</param>
        /// <returns>A boolean indicating successful delivery or serialization.</returns>
        Task<bool> ReportIncidentAsync(ThreatArtifact artifact);
    }
}
