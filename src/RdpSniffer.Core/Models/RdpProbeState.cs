namespace RdpSniffer.Core.Models;

/// <summary>Result state of probing a single address.</summary>
public enum RdpProbeState
{
    /// <summary>Skipped (reserved for future use; not produced by the current version).</summary>
    Skipped = 0,

    /// <summary>Port is not open / a connection could not be established.</summary>
    PortNotOpen,

    /// <summary>Port is open (TCP reachable; result of port-probing mode).</summary>
    PortOpen,

    /// <summary>Full login verification succeeded (simulated Remote Desktop Connection login succeeded).</summary>
    LoginSucceeded,

    /// <summary>Full login verification failed (credentials rejected / login timeout, etc.).</summary>
    LoginFailed,

    /// <summary>The probe failed with an unexpected error.</summary>
    ProbeFailed,
}
