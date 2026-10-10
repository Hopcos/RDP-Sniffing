using System.ComponentModel.DataAnnotations;

namespace RdpSniffer.Core.Options;

/// <summary>
/// All configuration for the RDP detection service, mapped from the "RdpDetection" section of appsettings.json.
/// Every runtime setting (subnet, excluded addresses, port, verification mode, credentials, timeouts,
/// concurrency, scheduling, report) is managed centrally here.
/// </summary>
public sealed class RdpDetectionOptions
{
    public const string SectionName = "RdpDetection";

    // ---------- Scan range ----------

    /// <summary>
    /// The network to scan. Supports CIDR notation (e.g. "10.0.5.0/24") or a plain IP
    /// (e.g. "10.0.5.0", combined with <see cref="PrefixLength"/>).
    /// </summary>
    [Required(ErrorMessage = "Network is required")]
    public string Network { get; set; } = "10.0.5.0/24";

    /// <summary>Subnet prefix length; only used when <see cref="Network"/> carries no "/prefix".</summary>
    [Range(0, 32, ErrorMessage = "PrefixLength must be between 0 and 32")]
    public int PrefixLength { get; set; } = 24;

    /// <summary>Addresses to exclude (e.g. the scanner host itself, 10.0.5.88). Standard IPv4 format expected.</summary>
    public List<string> ExcludedAddresses { get; set; } = new();

    /// <summary>Maximum number of targets per scan; protects against huge misconfigured networks (e.g. /8 or /0) exhausting resources.</summary>
    [Range(1, int.MaxValue, ErrorMessage = "MaxScanAddresses must be greater than 0")]
    public int MaxScanAddresses { get; set; } = 65536;

    /// <summary>Whether to include the network address (e.g. .0 for /24) in the scan. Defaults to false.</summary>
    public bool IncludeNetworkAddress { get; set; }

    /// <summary>Whether to include the broadcast address (e.g. .255 for /24) in the scan. Defaults to true (covers the full "1 ~ 255" detection range).</summary>
    public bool IncludeBroadcastAddress { get; set; } = true;

    // ---------- RDP endpoint ----------

    /// <summary>RDP service port.</summary>
    [Range(1, 65535, ErrorMessage = "Port must be between 1 and 65535")]
    public int Port { get; set; } = 3389;

    // ---------- Verification mode ----------

    /// <summary>
    /// Whether full RDP connectivity verification (credential-based login) is enabled.
    /// true  = simulate a complete login using the system MSTSC component (same client stack as Remote Desktop
    ///         Connection); requires <see cref="Credentials"/>.
    /// false = only check whether the RDP connection is open (TCP reachability + optional RDP handshake check);
    ///         no user name or password required.
    /// </summary>
    public bool VerifyCredentials { get; set; }

    /// <summary>Credential configuration (required only when VerifyCredentials=true).</summary>
    public CredentialOptions Credentials { get; set; } = new();

    /// <summary>
    /// In port-probing mode, whether a valid RDP handshake response (X.224 connection confirm / TLS negotiation)
    /// is required to consider the port "open". false (default) treats any successful TCP connect as open;
    /// true is stricter against non-RDP services.
    /// </summary>
    public bool RequireRdpBanner { get; set; }

    /// <summary>
    /// Whether to fetch and report the TLS certificate subject name (CN) of every open RDP endpoint
    /// (X.224 → TLS handshake, no login). Requires the server to offer NLA/TLS; legacy non-TLS servers
    /// are reported without a certificate name. Defaults to true.
    /// </summary>
    public bool CollectCertificateName { get; set; } = true;

    // ---------- Timeouts (seconds) ----------

    /// <summary>TCP connect timeout (seconds).</summary>
    [Range(1, 300, ErrorMessage = "ConnectTimeoutSeconds must be between 1 and 300")]
    public int ConnectTimeoutSeconds { get; set; } = 3;

    /// <summary>Timeout for waiting on the RDP handshake response (seconds); used only in port-probing mode.</summary>
    [Range(1, 300, ErrorMessage = "HandshakeTimeoutSeconds must be between 1 and 300")]
    public int HandshakeTimeoutSeconds { get; set; } = 3;

    /// <summary>Total timeout for a complete credential login verification (seconds).</summary>
    [Range(1, 3600, ErrorMessage = "LoginTimeoutSeconds must be between 1 and 3600")]
    public int LoginTimeoutSeconds { get; set; } = 15;

    // ---------- Concurrency ----------

    /// <summary>Maximum number of probe tasks running simultaneously.</summary>
    [Range(1, 1000, ErrorMessage = "MaxConcurrentProbes must be between 1 and 1000")]
    public int MaxConcurrentProbes { get; set; } = 50;

    // ---------- Scheduling ----------

    /// <summary>Whether to run one scan immediately after startup.</summary>
    public bool RunOnStart { get; set; } = true;

    /// <summary>Whether to keep scanning on a schedule; false means scan once and exit.</summary>
    public bool RunContinuously { get; set; } = true;

    /// <summary>Interval between scans (format "hh:mm:ss" or "d.hh:mm:ss"; minimum 5 seconds).</summary>
    public string ScanInterval { get; set; } = "00:10:00";

    // ---------- Login verification details ----------

    /// <summary>
    /// How the login-verification stage (VerifyCredentials=true) checks the credentials:
    /// Auto (default) = use the system MSTSC ActiveX component when it is available, otherwise fall back to
    /// the pure-protocol CredSSP/NLA client; Mstsc = always use the MSTSC ActiveX component; Protocol = always
    /// use the pure-protocol CredSSP/NLA client (no RDP ActiveX component required — a wire-level NLA handshake
    /// proves the credentials, same mechanism nmap/crackmapexec use).
    /// </summary>
    public LoginVerificationMethod LoginVerificationMethod { get; set; } = LoginVerificationMethod.Auto;

    /// <summary>Polling interval (milliseconds) while waiting for the login result.</summary>
    [Range(50, 10000, ErrorMessage = "MstscPollingIntervalMilliseconds must be between 50 and 10000")]
    public int MstscPollingIntervalMilliseconds { get; set; } = 500;

    /// <summary>Whether to enable CredSSP (Network Level Authentication / NLA).</summary>
    public bool MstscEnableCredSspSupport { get; set; } = true;

    /// <summary>Server authentication level: 0=none, 1=warn, 2=authenticate with the highest supported level (typical headless value), 3=self-signed allowed.</summary>
    [Range(0, 3, ErrorMessage = "MstscAuthenticationLevel must be between 0 and 3")]
    public int MstscAuthenticationLevel { get; set; } = 2;

    // ---------- Report ----------

    /// <summary>Scan report (JSON file) configuration.</summary>
    public ReportOptions Report { get; set; } = new();

    /// <summary>Parses the scan interval; guaranteed parseable after configuration validation.</summary>
    public TimeSpan GetScanInterval() => TimeSpan.Parse(ScanInterval);
}

/// <summary>Selects the client used by the login-verification stage.</summary>
public enum LoginVerificationMethod
{
    /// <summary>Use the system MSTSC ActiveX component when available; otherwise fall back to the protocol-based CredSSP/NLA client.</summary>
    Auto = 0,

    /// <summary>Always use the system MSTSC ActiveX component (same client stack as Remote Desktop Connection).</summary>
    Mstsc = 1,

    /// <summary>Always use the pure-protocol CredSSP/NLA client (no RDP ActiveX component required).</summary>
    Protocol = 2,
}

/// <summary>Credentials used for full login verification.</summary>
public sealed class CredentialOptions
{
    /// <summary>Account name (supports both "user" and "DOMAIN\\user" forms).</summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>Password (note: prefer environment variables / user secrets in production; see README).</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>Optional domain. When empty, the domain embedded in UserName is used.</summary>
    public string Domain { get; set; } = string.Empty;
}

/// <summary>Scan report output configuration.</summary>
public sealed class ReportOptions
{
    /// <summary>Whether to write the JSON report file.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Report file path (relative to the process working directory, or an absolute path).</summary>
    public string FilePath { get; set; } = "rdp-scan-report.json";
}
