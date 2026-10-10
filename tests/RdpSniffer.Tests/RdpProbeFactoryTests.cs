using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Options;
using RdpSniffer.Probes.Tcp;
using RdpSniffer.Service;
using RdpSniffer.Service.Composition;
using Xunit;

namespace RdpSniffer.Tests;

public class RdpProbeFactoryTests
{
    [Theory]
    [InlineData(false, false, RdpProbeKind.TcpBannerProbe)]
    [InlineData(false, true, RdpProbeKind.TcpBannerProbe)]
    [InlineData(true, false, RdpProbeKind.TcpBannerProbe)] // login verification impossible on non-Windows → fall back to port probing
    [InlineData(true, true, RdpProbeKind.MstscLoginProbe)]
    public void SelectKind_SelectsByConfigAndPlatform(bool verifyCredentials, bool isWindows, RdpProbeKind expected)
    {
        var options = new RdpDetectionOptions { VerifyCredentials = verifyCredentials };
        Assert.Equal(expected, RdpProbeFactory.SelectKind(options, isWindows));
    }

    private static ServiceProvider BuildProvider(RdpDetectionOptions options)
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));
        services.AddSingleton<IOptions<RdpDetectionOptions>>(Options.Create(options));
        services.AddSingleton<TcpRdpConnectionFactory>();
        services.AddSingleton<IRdpConnectionFactory>(sp => sp.GetRequiredService<TcpRdpConnectionFactory>());
        services.AddSingleton<IRdpCertificateNameProvider, FakeCertificateNameProvider>();
        services.AddSingleton<TcpRdpProbe>();
        services.AddSingleton<MstscLoginProbe>();
        services.AddSingleton<IMstscLoginClientFactory, FakeMstscLoginClientFactory>();
        services.AddSingleton<VerifyCredentialsProbe>(sp => new VerifyCredentialsProbe(
            sp.GetRequiredService<TcpRdpProbe>(),
            sp.GetRequiredService<MstscLoginProbe>(),
            sp.GetRequiredService<ILogger<VerifyCredentialsProbe>>()));
        services.AddSingleton<IRdpProbe>(RdpProbeComposition.Create);
        services.AddSingleton(TimeProvider.System);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void VerifyCredentialsFalse_CompositionReturnsTcpProbe()
    {
        using var provider = BuildProvider(new RdpDetectionOptions { VerifyCredentials = false });

        var probe = provider.GetRequiredService<IRdpProbe>();

        Assert.IsType<TcpRdpProbe>(probe);
    }

    [Fact]
    public void VerifyCredentialsTrueOnWindows_CompositionReturnsVerifyCredentialsProbe()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // this branch can only be reproduced on Windows
        }

        using var provider = BuildProvider(new RdpDetectionOptions { VerifyCredentials = true });

        var probe = provider.GetRequiredService<IRdpProbe>();

        Assert.IsType<VerifyCredentialsProbe>(probe);
    }

    [Fact]
    public void CompositionMatchesSelectKind()
    {
        var options = new RdpDetectionOptions { VerifyCredentials = false };
        using var provider = BuildProvider(options);

        var probe = provider.GetRequiredService<IRdpProbe>();
        var kind = RdpProbeFactory.SelectKind(options, OperatingSystem.IsWindows());

        Assert.Equal(kind == RdpProbeKind.MstscLoginProbe, probe is VerifyCredentialsProbe);
        Assert.Equal(kind == RdpProbeKind.TcpBannerProbe, probe is TcpRdpProbe);
    }
}
