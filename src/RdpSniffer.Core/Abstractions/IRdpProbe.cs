using RdpSniffer.Core.Models;

namespace RdpSniffer.Core.Abstractions;

/// <summary>
/// Probe abstraction. Every probe implementation (port probing, credential login verification) implements
/// this interface and is selected at application startup according to the configuration.
/// A new detection approach only needs to implement this interface and get registered.
/// </summary>
public interface IRdpProbe
{
    /// <summary>Probe name, used for logs and report diagnostics.</summary>
    string Name { get; }

    /// <summary>Probes a single target and returns a structured result; must not throw business exceptions to the caller.</summary>
    Task<RdpProbeResult> ProbeAsync(ProbeTarget target, CancellationToken cancellationToken);
}
