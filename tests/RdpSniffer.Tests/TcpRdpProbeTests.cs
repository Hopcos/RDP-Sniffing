using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;
using RdpSniffer.Probes.Tcp;
using Xunit;

namespace RdpSniffer.Tests;

public class TcpRdpProbeTests
{
    private static readonly ProbeTarget Target = ProbeTarget.Create(IPAddress.Parse("10.0.5.9"));

    private static (TcpRdpProbe Probe, FakeRdpConnectionFactory Factory) CreateProbe(
        Action<RdpDetectionOptions>? configure = null,
        IRdpCertificateNameProvider? certificateNameProvider = null)
    {
        var options = new RdpDetectionOptions
        {
            Network = "10.0.5.0/24",
            ConnectTimeoutSeconds = 1,
            HandshakeTimeoutSeconds = 1,
        };
        configure?.Invoke(options);

        var factory = new FakeRdpConnectionFactory();
        var probe = new TcpRdpProbe(factory, Options.Create(options), NullLogger<TcpRdpProbe>.Instance, certificateNameProvider);
        return (probe, factory);
    }

    [Fact]
    public async Task RefusedConnection_ReturnsPortNotOpen()
    {
        var (probe, factory) = CreateProbe();
        factory.ExceptionToThrow = new RdpConnectionException(RdpConnectionErrorKind.Refused, "Connection refused");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.False(result.RdpProtocolConfirmed);
        Assert.Contains("refused", result.Detail);
    }

    [Fact]
    public async Task TimeoutConnection_ReturnsPortNotOpen()
    {
        var (probe, factory) = CreateProbe();
        factory.ExceptionToThrow = new RdpConnectionException(RdpConnectionErrorKind.Timeout, "Connection timed out");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.Contains("timed out", result.Detail);
    }

    [Fact]
    public async Task UnreachableHost_ReturnsPortNotOpen()
    {
        var (probe, factory) = CreateProbe();
        factory.ExceptionToThrow = new RdpConnectionException(RdpConnectionErrorKind.HostUnreachable, "Host unreachable");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.Contains("unreachable", result.Detail);
    }

    [Fact]
    public async Task PortMode_TcpConnected_ReturnsPortOpen_WithCorrectPort()
    {
        var (probe, factory) = CreateProbe();
        factory.Connection = new FakeRdpConnection();

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortOpen, result.State);
        Assert.Null(result.RdpProtocolConfirmed);
        Assert.Equal(1, factory.Calls);
        Assert.Equal(3389, factory.LastPort);
        Assert.Equal(IPAddress.Parse("10.0.5.9"), factory.LastAddress);
    }

    [Fact]
    public async Task PortMode_ConnectionDisposed()
    {
        var (probe, factory) = CreateProbe();
        var connection = new FakeRdpConnection();
        factory.Connection = connection;

        await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.True(connection.Disposed);
    }

    [Fact]
    public async Task RequireBanner_NoResponse_ReturnsPortNotOpen()
    {
        var (probe, factory) = CreateProbe(o => o.RequireRdpBanner = true);
        factory.Connection = new FakeRdpConnection(); // no read data

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.False(result.RdpProtocolConfirmed);
        Assert.Contains("no RDP server response", result.Detail);
    }

    [Fact]
    public async Task RequireBanner_X224Confirm_ReturnsPortOpen_SendsHandshake()
    {
        var (probe, factory) = CreateProbe(o => o.RequireRdpBanner = true);
        var connection = new FakeRdpConnection(new byte[] { 0x03, 0x00, 0x00, 0x0D, 0x02, 0xF0, 0x80 });
        factory.Connection = connection;

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortOpen, result.State);
        Assert.True(result.RdpProtocolConfirmed);
        Assert.NotNull(connection.Written);
        Assert.Equal(
            RdpBannerParser.ConnectionRequestPayload.ToArray(),
            connection.Written);
    }

    [Fact]
    public async Task RequireBanner_TlsRecord_ReturnsPortOpen()
    {
        var (probe, factory) = CreateProbe(o => o.RequireRdpBanner = true);
        factory.Connection = new FakeRdpConnection(new byte[] { 0x16, 0x03, 0x01, 0x00, 0x2E });

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortOpen, result.State);
        Assert.True(result.RdpProtocolConfirmed);
    }

    [Fact]
    public async Task RequireBanner_UnknownResponse_ReturnsPortNotOpen()
    {
        var (probe, factory) = CreateProbe(o => o.RequireRdpBanner = true);
        factory.Connection = new FakeRdpConnection(new byte[] { 0x01, 0x02, 0x03 });

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.False(result.RdpProtocolConfirmed);
    }

    [Fact]
    public async Task FactoryGenericException_ReturnsProbeFailed()
    {
        var (probe, factory) = CreateProbe();
        factory.ExceptionToThrow = new InvalidOperationException("boom");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.ProbeFailed, result.State);
        Assert.Contains("boom", result.Detail);
    }

    [Fact]
    public async Task UserCancellation_Propagates()
    {
        var (probe, factory) = CreateProbe();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        factory.ExceptionToThrow = new OperationCanceledException();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => probe.ProbeAsync(Target, cts.Token));
    }

    [Fact]
    public async Task NonCancellationOce_OnConnect_DowngradedToPortNotOpen()
    {
        var (probe, factory) = CreateProbe();
        factory.ExceptionToThrow = new OperationCanceledException();
        using var cts = new CancellationTokenSource();

        var result = await probe.ProbeAsync(Target, cts.Token);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.Contains("timed out", result.Detail);
    }

    [Fact]
    public async Task CollectCertificateName_AttachesCertificateToPortOpenResult()
    {
        var provider = new FakeCertificateNameProvider { Result = "WIN-SERVERA" };
        var (probe, factory) = CreateProbe(certificateNameProvider: provider);
        factory.Connection = new FakeRdpConnection();

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortOpen, result.State);
        Assert.Equal("WIN-SERVERA", result.CertificateName);
        Assert.Equal(1, provider.Calls);
        Assert.Equal(3389, provider.LastPort);
        Assert.Equal("10.0.5.9", provider.LastTarget?.Ip);
    }

    [Fact]
    public async Task CollectCertificateNameDisabled_DoesNotCallProvider()
    {
        var provider = new FakeCertificateNameProvider { Result = "WIN-SERVERA" };
        var (probe, factory) = CreateProbe(o => o.CollectCertificateName = false, provider);
        factory.Connection = new FakeRdpConnection();

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortOpen, result.State);
        Assert.Null(result.CertificateName);
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public async Task CertificateProviderFailure_KeepsPortOpenWithNullCertificate()
    {
        var provider = new FakeCertificateNameProvider
        {
            Handler = (_, _, _) => throw new IOException("tls failed"),
        };
        var (probe, factory) = CreateProbe(certificateNameProvider: provider);
        factory.Connection = new FakeRdpConnection();

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortOpen, result.State);
        Assert.Null(result.CertificateName);
    }

    [Fact]
    public async Task CertificateFetchTimeout_KeepsPortOpenWithNullCertificate()
    {
        var provider = new FakeCertificateNameProvider
        {
            Handler = async (_, _, ct) =>
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
                return null;
            },
        };
        var (probe, factory) = CreateProbe(certificateNameProvider: provider);
        factory.Connection = new FakeRdpConnection();

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortOpen, result.State);
        Assert.Null(result.CertificateName);
    }
}
