using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;

namespace RdpSniffer.Core.Detection;

/// <summary>
/// Scan orchestrator: runs probes concurrently up to the configured limit, swallows probe exceptions into
/// results, aggregates statistics and produces an <see cref="RdpScanReport"/>. Pure logic with no real IO
/// (time is injected via TimeProvider), easy to unit test.
/// </summary>
public sealed class RdpScanRunner
{
    private readonly IRdpProbe _probe;
    private readonly IOptions<RdpDetectionOptions> _options;
    private readonly ILogger<RdpScanRunner> _logger;
    private readonly TimeProvider _timeProvider;

    public RdpScanRunner(
        IRdpProbe probe,
        IOptions<RdpDetectionOptions> options,
        ILogger<RdpScanRunner> logger,
        TimeProvider timeProvider)
    {
        _probe = probe;
        _options = options;
        _logger = logger;
        _timeProvider = timeProvider;
    }

    public async Task<RdpScanReport> ScanAsync(IReadOnlyList<ProbeTarget> targets, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var options = _options.Value;

        var startedAt = _timeProvider.GetTimestamp();
        var results = new System.Collections.Concurrent.ConcurrentBag<RdpProbeResult>();

        using var semaphore = new SemaphoreSlim(options.MaxConcurrentProbes);

        var tasks = targets.Select(async target =>
        {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var targetStartedAt = _timeProvider.GetTimestamp();
                RdpProbeResult result;
                try
                {
                    var raw = await _probe.ProbeAsync(target, cancellationToken).ConfigureAwait(false);
                    result = raw with { Target = target, Duration = _timeProvider.GetElapsedTime(targetStartedAt) };
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Probe {Ip} threw an unexpected exception; downgraded to ProbeFailed", target.Ip);
                    result = RdpProbeResult.Failed(target, ex) with
                    {
                        Duration = _timeProvider.GetElapsedTime(targetStartedAt),
                    };
                }

                results.Add(result);
            }
            finally
            {
                semaphore.Release();
            }
        }).ToArray();

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Scan cancelled (probed {Count} targets so far)", results.Count);
            throw;
        }

        var elapsed = _timeProvider.GetElapsedTime(startedAt);
        var ordered = results
            .OrderBy(r => ToUInt32(r.Target.Address))
            .ToList();

        return new RdpScanReport
        {
            GeneratedAtUtc = _timeProvider.GetUtcNow(),
            Network = options.Network,
            Port = options.Port,
            VerifyCredentials = options.VerifyCredentials,
            RequireRdpBanner = options.RequireRdpBanner,
            ExcludedAddresses = options.ExcludedAddresses?.ToArray() ?? Array.Empty<string>(),
            Summary = BuildSummary(ordered, elapsed),
            Results = ordered,
        };
    }

    private static RdpScanSummary BuildSummary(IReadOnlyCollection<RdpProbeResult> results, TimeSpan elapsed)
    {
        var summary = new RdpScanSummary { Total = results.Count, Elapsed = elapsed };
        foreach (var result in results)
        {
            switch (result.State)
            {
                case RdpProbeState.Skipped: summary = summary with { Skipped = summary.Skipped + 1 }; break;
                case RdpProbeState.PortNotOpen: summary = summary with { PortNotOpen = summary.PortNotOpen + 1 }; break;
                case RdpProbeState.PortOpen: summary = summary with { PortOpen = summary.PortOpen + 1 }; break;
                case RdpProbeState.LoginSucceeded: summary = summary with { LoginSucceeded = summary.LoginSucceeded + 1 }; break;
                case RdpProbeState.LoginFailed: summary = summary with { LoginFailed = summary.LoginFailed + 1 }; break;
                case RdpProbeState.ProbeFailed: summary = summary with { ProbeFailed = summary.ProbeFailed + 1 }; break;
                default: break;
            }
        }

        return summary;
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
}
