using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RdpSniffer.Core.Models;
using RdpSniffer.Probes.Tcp;
using Xunit;

namespace RdpSniffer.Tests;

/// <summary>
/// Loopback tests for <see cref="TlsCertificateNameProvider"/>: a minimal fake RDP server answers the
/// X.224 connection request and then performs a real TLS handshake with a self-signed certificate, so
/// the certificate-name extraction is exercised end to end.
/// </summary>
public class TlsCertificateNameProviderTests
{
    [Fact]
    public async Task TlsServer_PresentsCertificateName()
    {
        var (listener, port) = StartListener();
        var server = Task.Run(() => RunTlsServerAsync(listener, certificateName: "WIN-TEST-SERVER"));

        var provider = new TlsCertificateNameProvider();
        var name = await provider.GetCertificateNameAsync(
            ProbeTarget.Create(IPAddress.Loopback),
            port,
            TimeSpan.FromSeconds(10),
            CancellationToken.None);

        Assert.Equal("WIN-TEST-SERVER", name);
        await server;
    }

    [Fact]
    public async Task LegacyServerWithoutTls_ReturnsNull()
    {
        var (listener, port) = StartListener();
        var server = Task.Run(() => RunLegacyServerAsync(listener));

        var provider = new TlsCertificateNameProvider();
        var name = await provider.GetCertificateNameAsync(
            ProbeTarget.Create(IPAddress.Loopback),
            port,
            TimeSpan.FromSeconds(10),
            CancellationToken.None);

        Assert.Null(name);
        await server;
    }

    [Fact]
    public async Task ClosedPort_ReturnsNull()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop(); // nobody listens anymore

        var provider = new TlsCertificateNameProvider();
        var name = await provider.GetCertificateNameAsync(
            ProbeTarget.Create(IPAddress.Loopback),
            port,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.Null(name);
    }

    private static (TcpListener Listener, int Port) StartListener()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        return (listener, port);
    }

    private static async Task RunTlsServerAsync(TcpListener listener, string certificateName)
    {
        using (listener)
        using (var tcp = await listener.AcceptTcpClientAsync())
        using (var stream = tcp.GetStream())
        {
            var cr = new byte[19];
            await ReadAtLeastAsync(stream, cr, cr.Length);

            // X.224 connection confirm + RDP negotiation response (selectedProtocol = 0x01 SSL).
            await stream.WriteAsync(new byte[]
            {
                0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00,
                0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
            });
            await stream.FlushAsync();

            using var cert = CreateCertificate(certificateName);
            using var ssl = new SslStream(stream, leaveInnerStreamOpen: true, (_, _, _, _) => true);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = cert,
                EnabledSslProtocols = SslProtocols.Tls12,
            });
        }
    }

    private static async Task RunLegacyServerAsync(TcpListener listener)
    {
        using (listener)
        using (var tcp = await listener.AcceptTcpClientAsync())
        using (var stream = tcp.GetStream())
        {
            var cr = new byte[19];
            await ReadAtLeastAsync(stream, cr, cr.Length);

            // X.224 connection confirm WITHOUT the RDP protocol-negotiation block (legacy security).
            await stream.WriteAsync(new byte[] { 0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00 });
            await stream.FlushAsync();
        }
    }

    private static X509Certificate2 CreateCertificate(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var selfSigned = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(selfSigned.Export(X509ContentType.Pfx), null);
    }

    private static async Task<int> ReadAtLeastAsync(Stream stream, byte[] buffer, int minimum)
    {
        var total = 0;
        while (total < minimum)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total));
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }
}
