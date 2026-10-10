using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;

namespace RdpSniffer.Probes.Tcp;

/// <summary>
/// Port-probing probe (used when VerifyCredentials=false; cross-platform):
///   1) TCP connect; on failure → PortNotOpen (distinguishes refused / timeout / unreachable);
///   2) by default a successful TCP connect is PortOpen; when RequireRdpBanner=true,
///      a valid RDP handshake response (X.224 connection confirm / TLS negotiation) is required.
/// All network IO goes through the <see cref="IRdpConnectionFactory"/> abstraction so unit tests can inject fakes.
/// </summary>
public sealed class TcpRdpProbe : IRdpProbe
{
    private readonly IRdpConnectionFactory _connectionFactory;
    private readonly IRdpCertificateNameProvider? _certificateNameProvider;
    private readonly IOptions<RdpDetectionOptions> _options;
    private readonly ILogger<TcpRdpProbe> _logger;

    public TcpRdpProbe(
        IRdpConnectionFactory connectionFactory,
        IOptions<RdpDetectionOptions> options,
        ILogger<TcpRdpProbe> logger,
        IRdpCertificateNameProvider? certificateNameProvider = null)
    {
        _connectionFactory = connectionFactory;
        _options = options;
        _logger = logger;
        _certificateNameProvider = certificateNameProvider;
    }

    public string Name => "TcpBannerProbe";

    public async Task<RdpProbeResult> ProbeAsync(ProbeTarget target, CancellationToken cancellationToken)
    {
        var options = _options.Value;

        // 1) Connect
        IRdpConnection connection;
        try
        {
            connection = await _connectionFactory
                .ConnectAsync(target.Address, options.Port, TimeSpan.FromSeconds(options.ConnectTimeoutSeconds), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return RdpProbeResult.Create(target, RdpProbeState.PortNotOpen, protocol: false, detail: "Connection timed out");
        }
        catch (RdpConnectionException ex)
        {
            return RdpProbeResult.Create(
                target,
                RdpProbeState.PortNotOpen,
                protocol: false,
                detail: DescribeConnectError(ex));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unexpected exception while probing {Ip}:{Port} during connect", target.Ip, options.Port);
            return RdpProbeResult.Failed(target, ex);
        }

        await using var _ = connection;
        try
        {
            // 2) (Optional) RDP handshake confirmation
            if (!options.RequireRdpBanner)
            {
                var open = RdpProbeResult.Create(
                    target,
                    RdpProbeState.PortOpen,
                    protocol: null,
                    detail: $"TCP connection to {target.Ip}:{options.Port} succeeded (RDP port is open)");
                return await WithCertificateNameAsync(open, target, cancellationToken).ConfigureAwait(false);
            }

            var kind = await SendHandshakeAsync(connection, TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds), cancellationToken)
                .ConfigureAwait(false);

            return kind switch
            {
                RdpServerResponseKind.X224ConnectionConfirm
                    or RdpServerResponseKind.TlsHandshake
                    => await WithCertificateNameAsync(
                        RdpProbeResult.Create(
                            target,
                            RdpProbeState.PortOpen,
                            protocol: true,
                            detail: $"Received RDP handshake response ({kind})"),
                        target,
                        cancellationToken).ConfigureAwait(false),

                RdpServerResponseKind.None
                    => RdpProbeResult.Create(
                        target,
                        RdpProbeState.PortNotOpen,
                        protocol: false,
                        detail: "TCP connected, but no RDP server response was received within the handshake timeout (may not be an RDP service)"),

                _ => RdpProbeResult.Create(
                    target,
                    RdpProbeState.PortNotOpen,
                    protocol: false,
                    detail: "TCP connected, but the server response is not valid RDP protocol data"),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return RdpProbeResult.Create(target, RdpProbeState.PortNotOpen, protocol: false, detail: "RDP handshake timed out");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unexpected exception while probing {Ip}:{Port} during handshake", target.Ip, options.Port);
            return RdpProbeResult.Failed(target, ex);
        }
    }

    /// <summary>
    /// Fetches the server TLS certificate name for an open endpoint (when enabled/available) and attaches it
    /// to the result. Certificate lookup failures never change the probe outcome.
    /// </summary>
    private async Task<RdpProbeResult> WithCertificateNameAsync(
        RdpProbeResult result,
        ProbeTarget target,
        CancellationToken cancellationToken)
    {
        var options = _options.Value;
        if (!options.CollectCertificateName || _certificateNameProvider is null)
        {
            return result;
        }

        try
        {
            var name = await _certificateNameProvider
                .GetCertificateNameAsync(target, options.Port, TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds), cancellationToken)
                .ConfigureAwait(false);
            return result with { CertificateName = name };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to fetch the TLS certificate name of {Ip}; the port probe result is kept as is.", target.Ip);
            return result;
        }
    }

    private static async Task<RdpServerResponseKind> SendHandshakeAsync(
        IRdpConnection connection,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        await connection.WriteAsync(RdpBannerParser.ConnectionRequestPayload, timeoutCts.Token).ConfigureAwait(false);

        var buffer = new byte[512];
        var received = await connection.ReadAsync(buffer, timeoutCts.Token).ConfigureAwait(false);

        return RdpBannerParser.Classify(buffer.AsSpan(0, received));
    }

    private static string DescribeConnectError(RdpConnectionException ex)
    {
        var hint = ex.Kind switch
        {
            RdpConnectionErrorKind.Timeout => "Connection timed out (firewall may be dropping SYN packets)",
            RdpConnectionErrorKind.Refused => "Connection refused (port is closed or no service is listening)",
            RdpConnectionErrorKind.HostUnreachable => "Host unreachable",
            _ => "Connection failed",
        };

        return $"{hint}: {ex.Message}";
    }
}
