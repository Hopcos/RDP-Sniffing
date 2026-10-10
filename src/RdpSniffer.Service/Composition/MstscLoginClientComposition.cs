using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Options;
using RdpSniffer.Probes.CredSsp;
using RdpSniffer.Probes.Mstsc;

namespace RdpSniffer.Service.Composition;

/// <summary>
/// Composition root for the login-verification client: selects the IMstscLoginClientFactory implementation
/// based on <see cref="RdpDetectionOptions.LoginVerificationMethod"/>:
///   - Mstsc    → system MSTSC ActiveX (the same component Remote Desktop Connection / mstsc.exe uses);
///   - Protocol → pure wire-level CredSSP/NLA client (no RDP ActiveX component required);
///   - Auto     → MSTSC when the RDP ActiveX component is registered, otherwise the protocol client.
/// </summary>
public static class MstscLoginClientComposition
{
    public static IMstscLoginClientFactory Create(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<RdpDetectionOptions>>().Value;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("RdpSniffer.LoginClient");

        var useProtocol = options.LoginVerificationMethod switch
        {
            LoginVerificationMethod.Protocol => true,
            LoginVerificationMethod.Mstsc => false,
            _ => !RdpActiveXDetector.IsAvailable(),
        };

        if (useProtocol)
        {
            logger.LogInformation(
                "Login verification client: protocol-based CredSSP/NLA (pure wire-level handshake, no RDP ActiveX component required).");
            return services.GetRequiredService<CredSspLoginClientFactory>();
        }

        logger.LogInformation(
            "Login verification client: system MSTSC ActiveX (same component as Remote Desktop Connection).");
        return services.GetRequiredService<ComMstscLoginClientFactory>();
    }
}

/// <summary>Detects whether the RDP ActiveX component (MsRdpClient*) is registered on this machine.</summary>
public static class RdpActiveXDetector
{
    private static readonly string[] CandidateProgIds =
    {
        "MsRdpClient9NotSafeForScripting",
        "MsRdpClient8NotSafeForScripting",
        "MsRdpClient6NotSafeForScripting",
        "MsRdpClientNotSafeForScripting",
    };

    private static bool? _cached;

    public static bool IsAvailable()
    {
        if (_cached.HasValue)
        {
            return _cached.Value;
        }

        var available = OperatingSystem.IsWindows()
            && CandidateProgIds.Any(progId =>
            {
                try
                {
                    return Type.GetTypeFromProgID(progId) is not null;
                }
                catch
                {
                    return false;
                }
            });

        _cached = available;
        return available;
    }
}
