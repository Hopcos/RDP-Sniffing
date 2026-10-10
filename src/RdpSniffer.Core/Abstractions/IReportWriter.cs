using RdpSniffer.Core.Models;

namespace RdpSniffer.Core.Abstractions;

/// <summary>Scan report writer: persists the results of one scan round (currently a JSON file).</summary>
public interface IReportWriter
{
    Task WriteAsync(RdpScanReport report, CancellationToken cancellationToken);
}
