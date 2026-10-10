using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;

namespace RdpSniffer.Probes.Tcp;

/// <summary>
/// Fetches the TLS certificate subject name (CN) an RDP server presents, without performing any login:
/// TCP connect → X.224 connection request/confirm (protocol negotiation) → TLS handshake (certificate
/// validation disabled — RDP servers normally use self-signed certificates) → subject CN.
/// Returns null when the server uses legacy (non-TLS) RDP security or the handshake fails; it never
/// throws outward so a certificate lookup can never fail the port probe itself.
/// </summary>
public sealed class TlsCertificateNameProvider : IRdpCertificateNameProvider
{
    public async Task<string?> GetCertificateNameAsync(
        ProbeTarget target,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        var tcp = new TcpClient { NoDelay = true };
        try
        {
            var address = IPAddress.Parse(target.Ip);
            await tcp.ConnectAsync(address, port, timeoutCts.Token).ConfigureAwait(false);
            using var stream = tcp.GetStream();

            // 1) X.224 connection request/confirm — confirms TLS/NLA negotiation before anything else.
            if (!await IsTlsNegotiatedAsync(stream, timeoutCts.Token).ConfigureAwait(false))
            {
                return null; // legacy (non-TLS) RDP security → no certificate
            }

            // 2) TLS handshake; RDP servers usually present self-signed certificates, so validation is skipped.
            using var ssl = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);
#pragma warning disable SYSLIB0039 // TLS 1.0/1.1 are intentionally offered for legacy RDP servers
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target.Ip,
                EnabledSslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12,
            }, timeoutCts.Token).ConfigureAwait(false);
#pragma warning restore SYSLIB0039

            if (ssl.RemoteCertificate is null)
            {
                return null;
            }

            using var certificate = new X509Certificate2(ssl.RemoteCertificate);
            var name = certificate.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(name) ? null : name.Trim();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null; // any network/handshake anomaly → certificate unavailable (never fails the probe)
        }
        finally
        {
            tcp.Dispose();
        }
    }

    private static async Task<bool> IsTlsNegotiatedAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(RdpBannerParser.ConnectionRequestPayload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // TPKT header (4 bytes) carries the total frame length.
        var tpkt = new byte[4];
        var headerRead = await stream.ReadAtLeastAsync(tpkt, tpkt.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (headerRead < 4 || tpkt[0] != 0x03 || tpkt[1] != 0x00)
        {
            return false;
        }

        var frameLength = (tpkt[2] << 8) | tpkt[3];
        if (frameLength < 19 || frameLength > 512)
        {
            return false;
        }

        var frame = new byte[frameLength];
        tpkt.CopyTo(frame, 0);
        var bodyRead = await stream.ReadAtLeastAsync(frame.AsMemory(4), frameLength - 4, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (bodyRead < frameLength - 4 || frame[5] != 0xD0)
        {
            return false;
        }

        // selectedProtocol (4 bytes, little-endian) at the end of the negotiation block:
        // 0 = PROTOCOL_RDP (legacy security); anything else means TLS is supported.
        var selectedProtocol = frame[15] | (frame[16] << 8) | (frame[17] << 16) | (frame[18] << 24);
        return selectedProtocol != 0;
    }
}
