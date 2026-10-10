using Microsoft.Extensions.Logging;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;

namespace RdpSniffer.Core.Detection;

/// <summary>
/// Two-stage probe used in VerifyCredentials=true mode:
///   1) The availability stage first checks whether the RDP connection is open (identical semantics and
///      results as VerifyCredentials=false, i.e. TCP reachability + optional RDP handshake confirmation),
///      and that result is kept and reported, so open endpoints are never lost;
///   2) For endpoints confirmed open, the full login-verification stage (MSTSC-based, simulating Remote
///      Desktop Connection) verifies the credentials.
/// If the login stage cannot even establish a session (e.g. the RDP ActiveX component is missing) while
/// the port is open, the target is reported as <see cref="RdpProbeState.LoginFailed"/> with the reason.
/// </summary>
public sealed class VerifyCredentialsProbe : IRdpProbe
{
    /// <summary>Prefix used when the port is open but the login stage could not be completed.</summary>
    public const string OpenButVerificationUnavailable =
        "RDP port is open, but login verification could not be completed";

    private readonly IRdpProbe _portProbe;
    private readonly IRdpProbe _loginProbe;
    private readonly ILogger<VerifyCredentialsProbe> _logger;

    public VerifyCredentialsProbe(
        IRdpProbe portProbe,
        IRdpProbe loginProbe,
        ILogger<VerifyCredentialsProbe> logger)
    {
        _portProbe = portProbe;
        _loginProbe = loginProbe;
        _logger = logger;
    }

    public string Name => "VerifyCredentialsProbe";

    public async Task<RdpProbeResult> ProbeAsync(ProbeTarget target, CancellationToken cancellationToken)
    {
        // Stage 1: availability check (kept and reported exactly like port-probing mode).
        var port = await _portProbe.ProbeAsync(target, cancellationToken).ConfigureAwait(false);
        if (port.State != RdpProbeState.PortOpen)
        {
            return port;
        }

        // Stage 2: full login verification on endpoints confirmed open.
        var login = await _loginProbe.ProbeAsync(target, cancellationToken).ConfigureAwait(false);
        var duration = port.Duration + login.Duration;

        if (login.State is RdpProbeState.LoginSucceeded or RdpProbeState.LoginFailed)
        {
            return login with { Duration = duration, CertificateName = port.CertificateName };
        }

        // The port is open, but the login stage could not be performed/established
        // (e.g. the RDP ActiveX component is missing, or session negotiation failed).
        _logger.LogWarning(
            "RDP port {Ip} is open, but the login verification could not be completed: {Detail}",
            target.Ip,
            login.Detail);
        return RdpProbeResult.Create(
            target,
            RdpProbeState.LoginFailed,
            protocol: login.RdpProtocolConfirmed ?? true,
            detail: login.Detail is null
                ? OpenButVerificationUnavailable
                : $"{OpenButVerificationUnavailable}: {login.Detail}",
            certificateName: port.CertificateName,
            atUtc: login.CheckedAtUtc) with { Duration = duration };
    }
}
