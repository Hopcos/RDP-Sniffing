namespace RdpSniffer.Core.Models;

/// <summary>Aggregate statistics for one scan round.</summary>
public sealed record RdpScanSummary
{
    public int Total { get; init; }
    public int Skipped { get; init; }
    public int PortNotOpen { get; init; }
    public int PortOpen { get; init; }
    public int LoginSucceeded { get; init; }
    public int LoginFailed { get; init; }
    public int ProbeFailed { get; init; }

    /// <summary>Total elapsed time of the scan round (including concurrency queueing).</summary>
    public TimeSpan Elapsed { get; init; }
}

/// <summary>Complete report for one scan round (configuration snapshot + summary + details).</summary>
public sealed record RdpScanReport
{
    public DateTimeOffset GeneratedAtUtc { get; init; }

    // Configuration snapshot, useful for auditing which configuration produced these results.
    public string Network { get; init; } = string.Empty;
    public int Port { get; init; }
    public bool VerifyCredentials { get; init; }
    public bool RequireRdpBanner { get; init; }
    public IReadOnlyList<string> ExcludedAddresses { get; init; } = Array.Empty<string>();

    public RdpScanSummary Summary { get; init; } = new();

    public IReadOnlyList<RdpProbeResult> Results { get; init; } = Array.Empty<RdpProbeResult>();
}
