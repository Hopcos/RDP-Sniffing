using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;

namespace RdpSniffer.Service;

/// <summary>
/// Scan hosted service: scans right after startup (optional), then periodically at ScanInterval until the
/// process exits. Each round: calculate targets → probe concurrently → log the summary → write the JSON report.
/// </summary>
public sealed class RdpScanWorker : BackgroundService
{
    private readonly RdpTargetCalculator _calculator;
    private readonly RdpScanRunner _runner;
    private readonly IOptions<RdpDetectionOptions> _options;
    private readonly IReportWriter _reportWriter;
    private readonly TimeProvider _timeProvider;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<RdpScanWorker> _logger;

    public RdpScanWorker(
        RdpTargetCalculator calculator,
        RdpScanRunner runner,
        IOptions<RdpDetectionOptions> options,
        IReportWriter reportWriter,
        TimeProvider timeProvider,
        IHostApplicationLifetime lifetime,
        ILogger<RdpScanWorker> logger)
    {
        _calculator = calculator;
        _runner = runner;
        _options = options;
        _reportWriter = reportWriter;
        _timeProvider = timeProvider;
        _lifetime = lifetime;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var options = _options.Value;
        _logger.LogInformation(
            "RDP detection service started: Network={Network}, Excluded=[{Excluded}], Port={Port}, VerifyCredentials={VerifyCredentials}",
            options.Network,
            string.Join(", ", options.ExcludedAddresses ?? new List<string>()),
            options.Port,
            options.VerifyCredentials);

        if (options.RunOnStart)
        {
            await RunOnceAsync(stoppingToken).ConfigureAwait(false);
        }

        if (!options.RunContinuously)
        {
            _logger.LogInformation("RunContinuously=false; single scan completed, service is exiting.");
            _lifetime.StopApplication(); // Request the host to stop; otherwise the generic host keeps waiting for a shutdown signal
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(options.GetScanInterval(), _timeProvider, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            await RunOnceAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        try
        {
            var targets = _calculator.Calculate(options);
            _logger.LogInformation(
                "Starting scan of {Count} addresses (concurrency limit {Concurrency}, timeouts: connect {ConnectTimeout}s / handshake {HandshakeTimeout}s / login {LoginTimeout}s)…",
                targets.Count,
                options.MaxConcurrentProbes,
                options.ConnectTimeoutSeconds,
                options.HandshakeTimeoutSeconds,
                options.LoginTimeoutSeconds);

            var report = await _runner.ScanAsync(targets, cancellationToken).ConfigureAwait(false);

            LogSummary(report);
            await _reportWriter.WriteAsync(report, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _logger.LogInformation("Scan cancelled.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "This scan round failed.");
        }
    }

    private void LogSummary(RdpScanReport report)
    {
        var summary = report.Summary;
        _logger.LogInformation(
            "Scan completed: total {Total}, not open {PortNotOpen}, port open {PortOpen}, login succeeded {LoginSucceeded}, login failed {LoginFailed}, probe failed {ProbeFailed}, elapsed {Elapsed}",
            summary.Total,
            summary.PortNotOpen,
            summary.PortOpen,
            summary.LoginSucceeded,
            summary.LoginFailed,
            summary.ProbeFailed,
            summary.Elapsed);

        // "Available" = the RDP connection is open: port mode outputs PortOpen; credential mode outputs
        // LoginSucceeded/LoginFailed for endpoints whose port was confirmed open (even when login verification
        // itself failed, e.g. wrong credentials or a missing RDP ActiveX component).
        var open = report.Results.Where(r => r.State is RdpProbeState.PortOpen or RdpProbeState.LoginSucceeded or RdpProbeState.LoginFailed).ToList();
        if (open.Count > 0)
        {
            _logger.LogInformation("RDP available addresses ({Count}): {Addresses}",
                open.Count,
                string.Join(", ", open.Select(r => FormatAvailable(r))));
        }

        var loginFailed = report.Results.Where(r => r.State == RdpProbeState.LoginFailed).ToList();
        if (loginFailed.Count > 0)
        {
            _logger.LogWarning("RDP open but login failed ({Count}): {Addresses}",
                loginFailed.Count,
                string.Join(", ", loginFailed.Select(r => r.Target.Ip)));
        }
    }

    private static string FormatAvailable(RdpProbeResult result)
    {
        var certificate = result.CertificateName is { Length: > 0 } name
            ? $"[Cert: {name}]"
            : "[Cert: n/a]";
        return $"{result.Target.Ip} {certificate}";
    }
}
