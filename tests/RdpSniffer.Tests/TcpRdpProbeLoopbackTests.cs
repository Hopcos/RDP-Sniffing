using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;
using RdpSniffer.Probes.Tcp;
using Xunit;

namespace RdpSniffer.Tests;

/// <summary>
/// End-to-end probe tests over a real loopback TCP connection (validates the real IO path of
/// TcpRdpProbe + TcpRdpConnectionFactory).
/// </summary>
public class TcpRdpProbeLoopbackTests
{
    private static readonly byte[] FakeX224Confirm =
    {
        0x03, 0x00, 0x00, 0x0D, 0x02, 0xF0, 0x80, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x00,
    };

    private static TcpRdpProbe CreateProbe(bool requireBanner, int port = 3389, int handshakeTimeoutSeconds = 1)
    {
        var options = new RdpDetectionOptions
        {
            Network = "127.0.0.0/24",
            Port = port,
            RequireRdpBanner = requireBanner,
            ConnectTimeoutSeconds = 2,
            HandshakeTimeoutSeconds = handshakeTimeoutSeconds,
        };

        var factory = new TcpRdpConnectionFactory();
        return new TcpRdpProbe(factory, Options.Create(options), NullLogger<TcpRdpProbe>.Instance);
    }

    private static int GetClosedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop(); // the released port is very likely still free; used for the "not open" test
        return port;
    }

    [Fact]
    public async Task RealRdpServer_HandshakeConfirmed()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var server = Task.Run(async () =>
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                using var client = await listener.AcceptTcpClientAsync(cts.Token);
                await using var stream = client.GetStream();

                // Read the complete X.224 connection request before replying.
                var buffer = new byte[RdpBannerParser.ConnectionRequestPayload.Length];
                await stream.ReadExactlyAsync(buffer, cts.Token);
                await stream.WriteAsync(FakeX224Confirm, cts.Token);
            });

            var probe = CreateProbe(requireBanner: true, port: port);
            var result = await probe.ProbeAsync(
                ProbeTarget.Create(IPAddress.Loopback),
                CancellationToken.None);
            await server;

            Assert.Equal(RdpProbeState.PortOpen, result.State);
            Assert.True(result.RdpProtocolConfirmed);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task UnusedPort_ReportedNotOpen()
    {
        var port = GetClosedPort();
        var options = new RdpDetectionOptions
        {
            Network = "127.0.0.0/24",
            Port = port,
            ConnectTimeoutSeconds = 2,
        };
        var factory = new TcpRdpConnectionFactory();
        var probe = new TcpRdpProbe(factory, Options.Create(options), NullLogger<TcpRdpProbe>.Instance);

        var result = await probe.ProbeAsync(ProbeTarget.Create(IPAddress.Loopback), CancellationToken.None);

        // The detail may say "refused" or "timed out" depending on the local firewall policy
        // (normal Windows loopback usually returns RST → "refused"; some restricted environments
        // silently drop SYN → "timed out"; both have the same meaning).
        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.True(
            result.Detail!.Contains("refused") || result.Detail.Contains("timed out"),
            $"Detail should say refused or timed out, actual: {result.Detail}");
    }

    [Fact]
    public async Task SilentServer_HandshakeTimeout_NotOpen()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var server = Task.Run(async () =>
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                using var client = await listener.AcceptTcpClientAsync(cts.Token);
                await using var stream = client.GetStream();
                await stream.ReadAtLeastAsync(new byte[64], 1, throwOnEndOfStream: false, cts.Token); // reads but never replies
                await Task.Delay(TimeSpan.FromSeconds(2));
            });

            var options = new RdpDetectionOptions
            {
                Network = "127.0.0.0/24",
                Port = port,
                RequireRdpBanner = true,
                ConnectTimeoutSeconds = 2,
                HandshakeTimeoutSeconds = 1,
            };
            var factory = new TcpRdpConnectionFactory();
            var probe = new TcpRdpProbe(factory, Options.Create(options), NullLogger<TcpRdpProbe>.Instance);

            var result = await probe.ProbeAsync(ProbeTarget.Create(IPAddress.Loopback), CancellationToken.None);

            Assert.Equal(RdpProbeState.PortNotOpen, result.State);
            Assert.False(result.RdpProtocolConfirmed);
            await server;
        }
        finally
        {
            listener.Stop();
        }
    }
}
