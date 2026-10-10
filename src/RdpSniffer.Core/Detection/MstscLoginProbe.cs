using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;

namespace RdpSniffer.Core.Detection;

/// <summary>
/// Full login verification probe (used when VerifyCredentials=true).
/// It does not care "how to log in" (login is implemented by <see cref="IMstscLoginClient"/>, which is the
/// MSTSC COM component on Windows, the same client stack as mstsc.exe); it only orchestrates: builds the
/// login request and maps the result state.
/// </summary>
public sealed class MstscLoginProbe : IRdpProbe
{
    private readonly IMstscLoginClientFactory _clientFactory;
    private readonly IOptions<RdpDetectionOptions> _options;
    private readonly ILogger<MstscLoginProbe> _logger;

    public MstscLoginProbe(
        IMstscLoginClientFactory clientFactory,
        IOptions<RdpDetectionOptions> options,
        ILogger<MstscLoginProbe> logger)
    {
        _clientFactory = clientFactory;
        _options = options;
        _logger = logger;
    }

    public string Name => "MstscLoginProbe";

    public async Task<RdpProbeResult> ProbeAsync(ProbeTarget target, CancellationToken cancellationToken)
    {
        var options = _options.Value;

        // The factory can also fail (e.g. component unavailable); downgrade to ProbeFailed as well.
        IMstscLoginClient client;
        try
        {
            client = _clientFactory.Create();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create the RDP login client (target {Ip})", target.Ip);
            return RdpProbeResult.Failed(target, ex);
        }

        await using var _ = client;

        var request = new MstscLoginRequest
        {
            Host = target.Ip,
            Port = options.Port,
            UserName = options.Credentials.UserName,
            Domain = options.Credentials.Domain,
            Password = options.Credentials.Password,
            Timeout = TimeSpan.FromSeconds(options.LoginTimeoutSeconds),
            PollingIntervalMilliseconds = options.MstscPollingIntervalMilliseconds,
            EnableCredSspSupport = options.MstscEnableCredSspSupport,
            AuthenticationLevel = options.MstscAuthenticationLevel,
        };

        MstscLoginResult login;
        try
        {
            login = await client.LoginAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "RDP login probe {Ip} threw an unexpected exception", target.Ip);
            return RdpProbeResult.Failed(target, ex);
        }

        if (login.Succeeded)
        {
            return RdpProbeResult.Create(
                target,
                RdpProbeState.LoginSucceeded,
                protocol: true,
                detail: "RDP session established via the MSTSC client (simulated Remote Desktop Connection login succeeded)");
        }

        return MapFailure(target, login);
    }

    private static RdpProbeResult MapFailure(ProbeTarget target, MstscLoginResult login)
    {
        var description = string.IsNullOrWhiteSpace(login.ErrorDescription)
            ? login.FailureKind.ToString()
            : login.ErrorDescription;

        return login.FailureKind switch
        {
            // Cannot connect (port closed / unreachable / negotiation failure) → equivalent to "RDP not open on this address".
            MstscLoginFailureKind.ConnectionError
                or MstscLoginFailureKind.ProtocolError
                => RdpProbeResult.Create(
                    target,
                    RdpProbeState.PortNotOpen,
                    protocol: false,
                    detail: $"Unable to establish an RDP session: {description}"),

            // Credentials rejected → "RDP is open but login failed".
            MstscLoginFailureKind.AuthenticationError
                => RdpProbeResult.Create(
                    target,
                    RdpProbeState.LoginFailed,
                    protocol: true,
                    detail: $"Login rejected (user name or password may be wrong): {description}"),

            // Timeout and the rest.
            _ => RdpProbeResult.Create(
                target,
                RdpProbeState.LoginFailed,
                protocol: null,
                detail: $"Login verification did not complete: {description}"),
        };
    }
}
