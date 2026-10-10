using RdpSniffer.Core.Models;

namespace RdpSniffer.Core.Abstractions;

/// <summary>
/// Fetches the TLS certificate subject name (CN) that an RDP server presents, without completing a login.
/// Windows RDP servers configured with SSL/NLA authentication present a server certificate during the TLS
/// handshake (self-signed by default, e.g. "CN=WIN-XXXX"; a domain-joined machine may present its computer
/// certificate). This is the same identity the Remote Desktop client shows as the server name.
/// </summary>
public interface IRdpCertificateNameProvider
{
    /// <summary>
    /// Returns the server certificate subject name (CN), or null when the endpoint does not offer
    /// TLS/NLA (legacy RDP security) or the handshake fails. Failure never throws outward: it returns null.
    /// </summary>
    Task<string?> GetCertificateNameAsync(
        ProbeTarget target,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}
