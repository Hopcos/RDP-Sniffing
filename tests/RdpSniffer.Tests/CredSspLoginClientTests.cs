using RdpSniffer.Core.Abstractions;
using RdpSniffer.Probes.CredSsp;
using Xunit;

namespace RdpSniffer.Tests;

public class CredSspLoginClientTests
{
    [Fact]
    public async Task NonWindows_ReturnsProtocolErrorWithoutNetworkActivity()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // the non-Windows guard cannot be exercised on Windows
        }

        var client = new CredSspLoginClientFactory().Create();
        using var requestCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var result = await client.LoginAsync(
            new MstscLoginRequest
            {
                Host = "127.0.0.1",
                UserName = "user",
                Password = "password",
                Timeout = TimeSpan.FromSeconds(5),
            },
            requestCts.Token);

        Assert.False(result.Succeeded);
        Assert.Equal(MstscLoginFailureKind.ProtocolError, result.FailureKind);
    }
}
