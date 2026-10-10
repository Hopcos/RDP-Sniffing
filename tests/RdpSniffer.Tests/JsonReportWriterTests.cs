using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;
using RdpSniffer.Core.Reporting;
using Xunit;

namespace RdpSniffer.Tests;

public class JsonReportWriterTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(Path.GetTempPath(), $"rdp-report-test-{Guid.NewGuid():N}.json");
    private bool _cleanup = true;

    public void Dispose()
    {
        if (_cleanup && File.Exists(_tempPath))
        {
            File.Delete(_tempPath);
        }
    }

    private static RdpScanReport BuildReport()
    {
        var t1 = ProbeTarget.Create(IPAddress.Parse("10.0.5.1"));
        var t2 = ProbeTarget.Create(IPAddress.Parse("10.0.5.88"));
        return new RdpScanReport
        {
            GeneratedAtUtc = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
            Network = "10.0.5.0/24",
            Port = 3389,
            VerifyCredentials = true,
            RequireRdpBanner = false,
            ExcludedAddresses = new[] { "10.0.5.88" },
            Summary = new RdpScanSummary
            {
                Total = 2,
                PortOpen = 1,
                LoginSucceeded = 1,
                Elapsed = TimeSpan.FromSeconds(3),
            },
            Results = new[]
            {
                RdpProbeResult.Create(t1, RdpProbeState.PortOpen, protocol: true, detail: "TCP connection succeeded"),
                RdpProbeResult.Create(t2, RdpProbeState.LoginSucceeded, protocol: true, detail: "Login succeeded"),
            },
        };
    }

    private static JsonReportWriter CreateWriter(RdpDetectionOptions options)
        => new(Options.Create(options), NullLogger<JsonReportWriter>.Instance);

    [Fact]
    public async Task Disabled_NoFileCreated()
    {
        var options = new RdpDetectionOptions();
        options.Report.Enabled = false;
        options.Report.FilePath = _tempPath;

        await CreateWriter(options).WriteAsync(BuildReport(), CancellationToken.None);

        Assert.False(File.Exists(_tempPath));
    }

    [Fact]
    public async Task EmptyFilePath_NoThrow()
    {
        var options = new RdpDetectionOptions();
        options.Report.Enabled = true;
        options.Report.FilePath = "  ";

        await CreateWriter(options).WriteAsync(BuildReport(), CancellationToken.None);
    }

    [Fact]
    public async Task Enabled_WritesValidJsonReport()
    {
        var options = new RdpDetectionOptions();
        options.Report.Enabled = true;
        options.Report.FilePath = _tempPath;

        await CreateWriter(options).WriteAsync(BuildReport(), CancellationToken.None);

        Assert.True(File.Exists(_tempPath));
        var json = File.ReadAllText(_tempPath);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal("10.0.5.0/24", root.GetProperty("network").GetString());
        Assert.Equal(3389, root.GetProperty("port").GetInt32());
        Assert.Equal(2, root.GetProperty("summary").GetProperty("total").GetInt32());

        var results = root.GetProperty("results");
        Assert.Equal(2, results.GetArrayLength());

        var first = results[0];
        Assert.Equal("10.0.5.1", first.GetProperty("target").GetProperty("ip").GetString());
        Assert.Equal("PortOpen", first.GetProperty("state").GetString()); // enums serialized as strings
        Assert.True(first.GetProperty("rdpProtocolConfirmed").GetBoolean());
    }

    [Fact]
    public async Task MissingParentDirectory_Created()
    {
        var options = new RdpDetectionOptions();
        options.Report.Enabled = true;
        var nestedFile = Path.Combine(Path.GetTempPath(), $"rdp-parent-{Guid.NewGuid():N}", "sub", "report.json");
        options.Report.FilePath = nestedFile;
        _cleanup = false;
        try
        {
            await CreateWriter(options).WriteAsync(BuildReport(), CancellationToken.None);
            Assert.True(File.Exists(nestedFile));
        }
        finally
        {
            var root = Path.GetDirectoryName(Path.GetDirectoryName(nestedFile))!;
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
