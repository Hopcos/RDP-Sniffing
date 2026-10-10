namespace RdpSniffer.Core.Models;

/// <summary>Probe result for a single address.</summary>
public sealed record RdpProbeResult
{
    /// <summary>The probe target.</summary>
    public required ProbeTarget Target { get; init; }

    /// <summary>Result state.</summary>
    public RdpProbeState State { get; init; }

    /// <summary>Whether the RDP protocol was confirmed (the server returned an X.224 connection confirm or TLS negotiation). null = protocol not verified.</summary>
    public bool? RdpProtocolConfirmed { get; init; }

    /// <summary>Elapsed time of this probe.</summary>
    public TimeSpan Duration { get; init; }

    /// <summary>Human readable note (failure reason, handshake outcome, etc.).</summary>
    public string? Detail { get; init; }

    /// <summary>
    /// TLS certificate subject name (CN) presented by the RDP server (e.g. "WIN-XXXX" or the machine
    /// certificate name). null when the server does not offer TLS/NLA or the fetch was skipped/failed.
    /// </summary>
    public string? CertificateName { get; init; }

    /// <summary>When the probe finished (UTC).</summary>
    public DateTimeOffset CheckedAtUtc { get; init; }

    public static RdpProbeResult Create(
        ProbeTarget target,
        RdpProbeState state,
        bool? protocol = null,
        string? detail = null,
        string? certificateName = null,
        DateTimeOffset? atUtc = null)
        => new()
        {
            Target = target,
            State = state,
            RdpProtocolConfirmed = protocol,
            Detail = detail,
            CertificateName = certificateName,
            CheckedAtUtc = atUtc ?? DateTimeOffset.UtcNow,
        };

    /// <summary>Fallback result when the probe throws.</summary>
    public static RdpProbeResult Failed(ProbeTarget target, Exception ex)
        => new()
        {
            Target = target,
            State = RdpProbeState.ProbeFailed,
            Detail = ex.Message,
            CheckedAtUtc = DateTimeOffset.UtcNow,
        };
}
