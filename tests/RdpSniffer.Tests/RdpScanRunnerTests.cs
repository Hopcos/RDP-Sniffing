using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;
using Xunit;

namespace RdpSniffer.Tests;

public class RdpScanRunnerTests
{
    private static RdpDetectionOptions BuildOptions(int maxConcurrent = 2)
        => new()
        {
            Network = "10.0.5.0/24",
            MaxConcurrentProbes = maxConcurrent,
        };

    private static List<ProbeTarget> Targets(params string[] ips)
        => ips.Select(ip => ProbeTarget.Create(IPAddress.Parse(ip))).ToList();

    private static RdpScanRunner CreateRunner(FakeProbe probe, RdpDetectionOptions? options = null)
        => new(probe, Options.Create(options ?? BuildOptions()), NullLogger<RdpScanRunner>.Instance, TimeProvider.System);

    [Fact]
    public async Task AllSucceeded_ResultsSortedAscending_SummaryCorrect()
    {
        var probe = new FakeProbe();
        var runner = CreateRunner(probe, BuildOptions(8));

        var report = await runner.ScanAsync(
            Targets("10.0.5.10", "10.0.5.2", "10.0.5.1"),
            CancellationToken.None);

        Assert.Equal(3, probe.Calls);
        Assert.Equal(3, report.Results.Count);
        Assert.Equal(new[] { "10.0.5.1", "10.0.5.2", "10.0.5.10" }, report.Results.Select(r => r.Target.Ip));
        Assert.Equal(3, report.Summary.Total);
        Assert.Equal(3, report.Summary.PortOpen);
        Assert.Equal(0, report.Summary.PortNotOpen);
        Assert.True(report.Summary.Elapsed >= TimeSpan.Zero);
    }

    [Fact]
    public async Task ConcurrencyLimitRespected()
    {
        var probe = new FakeProbe
        {
            Handler = async (_, _) =>
            {
                await Task.Delay(30);
                return RdpProbeResult.Create(ProbeTarget.Create(IPAddress.Parse("10.0.5.1")), RdpProbeState.PortOpen);
            },
        };
        var runner = CreateRunner(probe, BuildOptions(maxConcurrent: 2));

        var ips = Enumerable.Range(1, 8).Select(i => $"10.0.5.{i}").ToArray();
        var report = await runner.ScanAsync(Targets(ips), CancellationToken.None);

        Assert.Equal(8, probe.Calls);
        Assert.Equal(2, probe.MaxConcurrent); // at most 2 probes running simultaneously
        Assert.Equal(8, report.Results.Count);
    }

    [Fact]
    public async Task SingleProbeThrows_DowngradedToProbeFailed_OthersUnaffected()
    {
        var probe = new FakeProbe
        {
            Handler = async (target, _) =>
            {
                if (target.Ip == "10.0.5.5")
                {
                    throw new InvalidOperationException("probe boom");
                }

                return RdpProbeResult.Create(target, RdpProbeState.PortOpen);
            },
        };
        var runner = CreateRunner(probe, BuildOptions(4));

        var report = await runner.ScanAsync(
            Targets("10.0.5.5", "10.0.5.1"),
            CancellationToken.None);

        var failed = Assert.Single(report.Results, r => r.State == RdpProbeState.ProbeFailed);
        Assert.Equal("10.0.5.5", failed.Target.Ip);
        Assert.Contains("probe boom", failed.Detail);
        Assert.Equal(1, report.Summary.PortOpen);
        Assert.Equal(1, report.Summary.ProbeFailed);
    }

    [Fact]
    public async Task EmptyTargets_EmptyReport()
    {
        var probe = new FakeProbe();
        var runner = CreateRunner(probe);

        var report = await runner.ScanAsync(Array.Empty<ProbeTarget>(), CancellationToken.None);

        Assert.Empty(report.Results);
        Assert.Equal(0, report.Summary.Total);
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task CancellationDuringScan_ThrowsOperationCanceledException()
    {
        var probe = new FakeProbe
        {
            Handler = async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                return RdpProbeResult.Create(ProbeTarget.Create(IPAddress.Parse("10.0.5.1")), RdpProbeState.PortOpen);
            },
        };
        var runner = CreateRunner(probe);

        using var cts = new CancellationTokenSource();
        var scan = runner.ScanAsync(Targets("10.0.5.1", "10.0.5.2"), cts.Token);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scan);
    }

    [Fact]
    public async Task ReportContainsConfigurationSnapshot()
    {
        var probe = new FakeProbe();
        var runner = CreateRunner(probe, BuildOptions());

        var report = await runner.ScanAsync(Targets("10.0.5.1"), CancellationToken.None);

        Assert.Equal("10.0.5.0/24", report.Network);
        Assert.Equal(3389, report.Port);
        Assert.False(report.VerifyCredentials);
        Assert.False(report.RequireRdpBanner);
    }

    [Fact]
    public async Task ResultsCarryElapsedDuration()
    {
        var probe = new FakeProbe
        {
            Handler = async (target, _) =>
            {
                await Task.Delay(10);
                return RdpProbeResult.Create(target, RdpProbeState.PortOpen);
            },
        };
        var runner = CreateRunner(probe);

        var report = await runner.ScanAsync(Targets("10.0.5.1"), CancellationToken.None);

        Assert.True(report.Results[0].Duration > TimeSpan.Zero);
    }
}
