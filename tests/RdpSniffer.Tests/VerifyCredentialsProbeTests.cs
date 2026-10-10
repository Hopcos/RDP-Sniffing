using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Models;
using Xunit;

namespace RdpSniffer.Tests;

public class VerifyCredentialsProbeTests
{
    private static readonly ProbeTarget Target = ProbeTarget.Create(IPAddress.Parse("10.0.5.21"));

    private static (VerifyCredentialsProbe Probe, FakeProbe Port, FakeProbe Login) CreateProbe()
    {
        var port = new FakeProbe();
        var login = new FakeProbe();
        var probe = new VerifyCredentialsProbe(port, login, NullLogger<VerifyCredentialsProbe>.Instance);
        return (probe, port, login);
    }

    [Fact]
    public async Task PortNotOpen_SkipsLogin_KeepsAvailabilityResult()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(
            RdpProbeResult.Create(t, RdpProbeState.PortNotOpen, protocol: false, detail: "Connection refused"));

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.PortNotOpen, result.State);
        Assert.Equal(0, login.Calls);
        Assert.Contains("Connection refused", result.Detail);
    }

    [Fact]
    public async Task PortOpen_LoginSucceeded_ReturnsLoginSucceeded()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(t, RdpProbeState.PortOpen));
        login.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(t, RdpProbeState.LoginSucceeded, protocol: true));

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginSucceeded, result.State);
        Assert.Equal(1, login.Calls);
    }

    [Fact]
    public async Task PortOpen_LoginRejected_ReturnsLoginFailed()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(t, RdpProbeState.PortOpen));
        login.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(
            t,
            RdpProbeState.LoginFailed,
            protocol: true,
            detail: "Login rejected (user name or password may be wrong): bad creds"));

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginFailed, result.State);
        Assert.Contains("user name or password", result.Detail);
    }

    [Fact]
    public async Task PortOpen_LoginCannotEstablishSession_ConvertedToLoginFailed_KeepsOpenFact()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(t, RdpProbeState.PortOpen, protocol: null));
        login.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(
            t,
            RdpProbeState.PortNotOpen,
            protocol: false,
            detail: "Unable to establish an RDP session: RDP ActiveX client component (MsRdpClient*) was not found; make sure the 'Remote Desktop Connection' component is installed."));

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        // The port is open → never lost; reported as LoginFailed with the reason.
        Assert.Equal(RdpProbeState.LoginFailed, result.State);
        Assert.Contains("RDP port is open, but login verification could not be completed", result.Detail);
        Assert.Contains("MsRdpClient", result.Detail);
    }

    [Fact]
    public async Task PortOpen_LoginProbeFailed_ConvertedToLoginFailed()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(t, RdpProbeState.PortOpen));
        login.Handler = (t, _) => Task.FromResult(RdpProbeResult.Failed(t, new InvalidOperationException("boom")));

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginFailed, result.State);
        Assert.Contains("RDP port is open, but login verification could not be completed", result.Detail);
    }

    [Fact]
    public async Task Durations_AccumulatedAcrossStages()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(
            RdpProbeResult.Create(t, RdpProbeState.PortOpen) with { Duration = TimeSpan.FromMilliseconds(5) });
        login.Handler = (t, _) => Task.FromResult(
            RdpProbeResult.Create(t, RdpProbeState.LoginSucceeded, protocol: true) with { Duration = TimeSpan.FromMilliseconds(10) });

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(TimeSpan.FromMilliseconds(15), result.Duration);
    }

    [Fact]
    public async Task UserCancellation_Propagates()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(RdpProbeResult.Create(t, RdpProbeState.PortOpen));
        login.Handler = (_, ct) => throw new OperationCanceledException(ct);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => probe.ProbeAsync(Target, cts.Token));
    }

    [Fact]
    public async Task CertificateName_FromPortStage_FlowsToLoginSucceededResult()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(
            RdpProbeResult.Create(t, RdpProbeState.PortOpen, certificateName: "WIN-CERTA"));
        login.Handler = (t, _) => Task.FromResult(
            RdpProbeResult.Create(t, RdpProbeState.LoginSucceeded, protocol: true));

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginSucceeded, result.State);
        Assert.Equal("WIN-CERTA", result.CertificateName);
    }

    [Fact]
    public async Task CertificateName_FromPortStage_FlowsToConvertedLoginFailedResult()
    {
        var (probe, port, login) = CreateProbe();
        port.Handler = (t, _) => Task.FromResult(
            RdpProbeResult.Create(t, RdpProbeState.PortOpen, certificateName: "WIN-CERTB"));
        login.Handler = (t, _) => Task.FromResult(
            RdpProbeResult.Create(t, RdpProbeState.ProbeFailed, detail: "cannot establish session"));

        var result = await probe.ProbeAsync(Target, CancellationToken.None);

        Assert.Equal(RdpProbeState.LoginFailed, result.State);
        Assert.Equal("WIN-CERTB", result.CertificateName);
    }
}
