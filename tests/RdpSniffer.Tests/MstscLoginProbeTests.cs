using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;
using Xunit;

namespace RdpSniffer.Tests;

public class MstscLoginProbeTests
{
    private static readonly ProbeTarget Target = ProbeTarget.Create(IPAddress.Parse("10.0.5.11"));

    private static (MstscLoginProbe Probe, FakeMstscLoginClientFactory Factory) CreateProbe(
        Action<RdpDetectionOptions>? configure = null)
    {
        var options = new RdpDetectionOptions
        {
            Network = "10.0.5.0/24",
            VerifyCredentials = true,
            Credentials = new CredentialOptions { UserName = "admin", Password = "secret", Domain = "CORP" },
            LoginTimeoutSeconds = 15,
        };
        configure?.Invoke(options);

        var factory = new FakeMstscLoginClientFactory();
        var probe = new MstscLoginProbe(factory, Options.Create(options), NullLogger<MstscLoginProbe>.Instance);
        return (probe, factory);
    }

    [Fact]
    public async Task SuccessfulLogin_ReturnsLoginSucceeded()
    {
        var (probe, factory) = CreateProbe();
        factory.Handler = (_, _) => MstscLoginResult.Ok();

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginSucceeded, result.State);
        Assert.True(result.RdpProtocolConfirmed);
    }

    [Fact]
    public async Task LoginRequest_CarriesHostPortCredentialsTimeout()
    {
        var (probe, factory) = CreateProbe(o =>
        {
            o.LoginTimeoutSeconds = 7;
            o.MstscPollingIntervalMilliseconds = 250;
            o.MstscEnableCredSspSupport = false;
            o.MstscAuthenticationLevel = 1;
        });
        factory.Handler = (_, _) => MstscLoginResult.Ok();

        await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.NotNull(factory.LastClient);
        var request = factory.LastClient!.LastRequest!;
        Assert.Equal("10.0.5.11", request.Host);
        Assert.Equal(3389, request.Port);
        Assert.Equal("admin", request.UserName);
        Assert.Equal("secret", request.Password);
        Assert.Equal("CORP", request.Domain);
        Assert.Equal(TimeSpan.FromSeconds(7), request.Timeout);
        Assert.Equal(250, request.PollingIntervalMilliseconds);
        Assert.False(request.EnableCredSspSupport);
        Assert.Equal(1, request.AuthenticationLevel);
    }

    [Fact]
    public async Task LoginSuccess_ClientDisposed()
    {
        var (probe, factory) = CreateProbe();
        factory.Handler = (_, _) => MstscLoginResult.Ok();

        await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.True(factory.LastClient!.Disposed);
    }

    [Fact]
    public async Task CredentialsRejected_ReturnsLoginFailed()
    {
        var (probe, factory) = CreateProbe();
        factory.Handler = (_, _) => MstscLoginResult.Fail(
            MstscLoginFailureKind.AuthenticationError,
            errorCode: "0x800706BE",
            description: "Wrong user name or password");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginFailed, result.State);
        Assert.True(result.RdpProtocolConfirmed);
        Assert.Contains("user name or password", result.Detail);
    }

    [Fact]
    public async Task ConnectionFailure_MappedToPortNotOpen()
    {
        var (probe, factory) = CreateProbe();
        factory.Handler = (_, _) => MstscLoginResult.Fail(
            MstscLoginFailureKind.ConnectionError,
            description: "Could not connect");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.Contains("Unable to establish an RDP session", result.Detail);
    }

    [Fact]
    public async Task LoginTimeout_ReturnsLoginFailed()
    {
        var (probe, factory) = CreateProbe();
        factory.Handler = (_, _) => MstscLoginResult.Fail(
            MstscLoginFailureKind.Timeout,
            description: "Login timed out");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginFailed, result.State);
        Assert.Contains("Login verification did not complete", result.Detail);
    }

    [Fact]
    public async Task ClientFactoryThrows_ReturnsProbeFailed()
    {
        var (probe, factory) = CreateProbe();
        factory.CreateException = new COMException_Stub();

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.ProbeFailed, result.State);
    }

    [Fact]
    public async Task ClientLoginThrows_ReturnsProbeFailed()
    {
        var (probe, factory) = CreateProbe();
        factory.Handler = (_, _) => throw new InvalidOperationException("client exploded");

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.ProbeFailed, result.State);
        Assert.Contains("client exploded", result.Detail);
    }

    [Fact]
    public async Task CancellationToken_Propagates()
    {
        var (probe, factory) = CreateProbe();
        factory.Handler = (_, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            return MstscLoginResult.Ok();
        };

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => probe.ProbeAsync(Target, cts.Token));
    }

    private sealed class COMException_Stub : Exception;
}
