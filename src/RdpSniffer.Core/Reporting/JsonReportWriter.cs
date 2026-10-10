using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;

namespace RdpSniffer.Core.Reporting;

/// <summary>
/// JSON report writer: serializes one scan round into an auditable JSON file (default rdp-scan-report.json).
/// Relative paths are resolved against the process working directory; missing parent directories are created.
/// </summary>
public sealed class JsonReportWriter : IReportWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly IOptions<RdpDetectionOptions> _options;
    private readonly ILogger<JsonReportWriter> _logger;

    public JsonReportWriter(
        IOptions<RdpDetectionOptions> options,
        ILogger<JsonReportWriter> logger)
    {
        _options = options;
        _logger = logger;
    }

    public async Task WriteAsync(RdpScanReport report, CancellationToken cancellationToken)
    {
        var options = _options.Value;
        if (options.Report is null || !options.Report.Enabled)
        {
            return;
        }

        var path = options.Report.FilePath;
        if (string.IsNullOrWhiteSpace(path))
        {
            _logger.LogWarning("Report.Enabled=true but Report.FilePath is empty; skipping the report write.");
            return;
        }

        EnsureParentDirectory(path);

        await using (var stream = File.Create(path))
        {
            await JsonSerializer.SerializeAsync(stream, report, SerializerOptions, cancellationToken).ConfigureAwait(false);
        }

        _logger.LogInformation("Scan report written to: {Path}", Path.GetFullPath(path));
    }

    internal static void EnsureParentDirectory(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }
}
