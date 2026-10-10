using RdpSniffer.Core.Options;

namespace RdpSniffer.Core.Detection;

/// <summary>Available probe kinds.</summary>
public enum RdpProbeKind
{
    /// <summary>TCP + RDP handshake port probing (cross-platform, no credentials required).</summary>
    TcpBannerProbe,

    /// <summary>Full login verification built on the system MSTSC component (Windows only).</summary>
    MstscLoginProbe,
}

/// <summary>
/// Probe selection rule (a pure function, easy to unit test):
///   VerifyCredentials=false             → TcpBannerProbe (only checks whether RDP is open);
///   VerifyCredentials=true and Windows  → MstscLoginProbe (full login simulating Remote Desktop Connection);
///   VerifyCredentials=true, not Windows → falls back to TcpBannerProbe (the composition root logs a warning).
/// Note: the actual DI wiring (composition root) lives in the host project RdpSniffer.Service
/// (RdpProbeComposition), because Core must not reference concrete probe implementation assemblies.
/// </summary>
public static class RdpProbeFactory
{
    public static RdpProbeKind SelectKind(RdpDetectionOptions options, bool processIsWindows)
    {
        if (options.VerifyCredentials && processIsWindows)
        {
            return RdpProbeKind.MstscLoginProbe;
        }

        return RdpProbeKind.TcpBannerProbe;
    }
}
