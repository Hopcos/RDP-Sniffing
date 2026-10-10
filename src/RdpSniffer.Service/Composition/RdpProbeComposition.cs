using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Options;
using RdpSniffer.Probes.Tcp;

namespace RdpSniffer.Service.Composition;

/// <summary>
/// Composition root: wires up the final <see cref="IRdpProbe"/> according to the configuration and the
/// runtime platform. The decision rule lives in the pure function <see cref="RdpProbeFactory.SelectKind"/>;
/// this type only adds logging and DI resolution.
/// </summary>
public static class RdpProbeComposition
{
    public static IRdpProbe Create(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<RdpDetectionOptions>>().Value;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("RdpSniffer.ProbeFactory");

        var kind = RdpProbeFactory.SelectKind(options, OperatingSystem.IsWindows());

        switch (kind)
        {
            case RdpProbeKind.MstscLoginProbe:
                logger.LogInformation(
                    "Verification mode: availability check first, then full login verification (client chosen by LoginVerificationMethod: Auto prefers the system MSTSC ActiveX and falls back to the protocol CredSSP/NLA client). Account={UserName}",
                    options.Credentials.UserName);
                return services.GetRequiredService<VerifyCredentialsProbe>();

            default:
                if (options.VerifyCredentials)
                {
                    logger.LogWarning(
                        "VerifyCredentials=true but the current process is not Windows; MSTSC login verification is unavailable. Falling back to port probing.");
                }
                else
                {
                    logger.LogInformation("Verification mode: port probing (only checks whether the RDP connection is open; no user name or password required).");
                }

                return services.GetRequiredService<TcpRdpProbe>();
        }
    }
}
