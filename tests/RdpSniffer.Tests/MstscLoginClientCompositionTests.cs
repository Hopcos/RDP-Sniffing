using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Options;
using RdpSniffer.Probes.CredSsp;
using RdpSniffer.Probes.Mstsc;
using RdpSniffer.Service.Composition;
using Xunit;

namespace RdpSniffer.Tests;

public class MstscLoginClientCompositionTests
{
    [Fact]
    public void MethodMstsc_ReturnsComMstscLoginClientFactory()
    {
        using var provider = BuildProvider(new RdpDetectionOptions { LoginVerificationMethod = LoginVerificationMethod.Mstsc });

        var factory = provider.GetRequiredService<IMstscLoginClientFactory>();

        Assert.IsType<ComMstscLoginClientFactory>(factory);
    }

    [Fact]
    public void MethodProtocol_ReturnsCredSspLoginClientFactory()
    {
        using var provider = BuildProvider(new RdpDetectionOptions { LoginVerificationMethod = LoginVerificationMethod.Protocol });

        var factory = provider.GetRequiredService<IMstscLoginClientFactory>();

        Assert.IsType<CredSspLoginClientFactory>(factory);
    }

    private static ServiceProvider BuildProvider(RdpDetectionOptions options)
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));
        services.AddSingleton<IOptions<RdpDetectionOptions>>(Options.Create(options));
        services.AddSingleton<ComMstscLoginClientFactory>();
        services.AddSingleton<CredSspLoginClientFactory>();
        services.AddSingleton<IMstscLoginClientFactory>(sp => MstscLoginClientComposition.Create(sp));
        return services.BuildServiceProvider();
    }
}
