namespace RdpSniffer.Core.Abstractions;

/// <summary>
/// MSTSC login verification client abstraction (used in VerifyCredentials=true mode).
/// The real implementation is built on the system Remote Desktop ActiveX component (same origin as mstsc.exe)
/// and runs on Windows; unit tests inject fakes to verify probe orchestration logic.
/// </summary>
public interface IMstscLoginClient : IAsyncDisposable
{
    Task<MstscLoginResult> LoginAsync(MstscLoginRequest request, CancellationToken cancellationToken);
}

/// <summary>Login client factory: creates one client per target.</summary>
public interface IMstscLoginClientFactory
{
    IMstscLoginClient Create();
}

/// <summary>Request parameters for one complete login verification.</summary>
public sealed record MstscLoginRequest
{
    public required string Host { get; init; }

    public int Port { get; init; } = 3389;

    public required string UserName { get; init; }

    public string Domain { get; init; } = string.Empty;

    public required string Password { get; init; }

    /// <summary>Total timeout for the whole login process.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>State polling interval.</summary>
    public int PollingIntervalMilliseconds { get; init; } = 500;

    public bool EnableCredSspSupport { get; init; } = true;

    public int AuthenticationLevel { get; init; } = 2;
}

/// <summary>Login failure category.</summary>
public enum MstscLoginFailureKind
{
    None,

    /// <summary>Could not establish a reliable connection with the target (port closed, network unreachable, or negotiation failure).</summary>
    ConnectionError,

    /// <summary>The server rejected the credentials (wrong user name or password).</summary>
    AuthenticationError,

    /// <summary>Login did not complete within the timeout.</summary>
    Timeout,

    /// <summary>Component/platform related error (e.g. the RDP ActiveX component is missing on this host).</summary>
    ProtocolError,
}

/// <summary>Result of one complete login verification.</summary>
public sealed record MstscLoginResult
{
    public bool Succeeded { get; init; }

    public MstscLoginFailureKind FailureKind { get; init; } = MstscLoginFailureKind.None;

    public string? ErrorCode { get; init; }

    public string? ErrorDescription { get; init; }

    public static MstscLoginResult Ok() => new() { Succeeded = true };

    public static MstscLoginResult Fail(
        MstscLoginFailureKind kind,
        string? errorCode = null,
        string? description = null)
        => new()
        {
            Succeeded = false,
            FailureKind = kind,
            ErrorCode = errorCode,
            ErrorDescription = description,
        };
}
