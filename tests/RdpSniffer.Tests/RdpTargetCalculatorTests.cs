using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;
using Xunit;

namespace RdpSniffer.Tests;

public class RdpTargetCalculatorTests
{
    private static RdpDetectionOptions Options(Action<RdpDetectionOptions>? configure = null)
    {
        var options = new RdpDetectionOptions();
        configure?.Invoke(options);
        return options;
    }

    private static List<string> Ips(IEnumerable<ProbeTarget> targets) => targets.Select(t => t.Ip).ToList();

    [Fact]
    public void DefaultConfig_Slash24_Excluding88_Yields254AscendingAddresses()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.0/24";
            o.ExcludedAddresses = new List<string> { "10.0.5.88" };
        });

        var ips = Ips(new RdpTargetCalculator().Calculate(options));

        Assert.Equal(254, ips.Count);
        Assert.DoesNotContain("10.0.5.88", ips);
        Assert.DoesNotContain("10.0.5.0", ips);            // network address excluded by default
        Assert.Contains("10.0.5.1", ips);
        Assert.Contains("10.0.5.255", ips);                // broadcast address included by default (full 1~255 range)
        Assert.Equal(ips, ips.OrderBy(ToUInt32).ToList()); // ascending numeric order
        Assert.Equal(ips.Distinct().Count(), ips.Count);
    }

    [Fact]
    public void IncludeNetworkAddress_YieldsDot0()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.0/24";
            o.IncludeNetworkAddress = true;
        });

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Contains("10.0.5.0", ips);
        Assert.Equal(256, ips.Count);
    }

    [Fact]
    public void ExcludeBroadcastAddress_OmitsDot255()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.0/24";
            o.IncludeBroadcastAddress = false;
            o.ExcludedAddresses = new List<string> { "10.0.5.88" };
        });

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Equal(253, ips.Count);
        Assert.DoesNotContain("10.0.5.255", ips);
        Assert.Contains("10.0.5.254", ips);
    }

    [Fact]
    public void Slash30_WithBroadcast_YieldsThreeHosts()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.4/30";
            o.IncludeBroadcastAddress = true;
        });

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Equal(new[] { "10.0.5.5", "10.0.5.6", "10.0.5.7" }, ips);
    }

    [Fact]
    public void Slash30_WithoutBroadcast_YieldsTwoHosts()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.4/30";
            o.IncludeBroadcastAddress = false;
        });

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Equal(new[] { "10.0.5.5", "10.0.5.6" }, ips);
    }

    [Fact]
    public void Slash31_BothAddressesUsable()
    {
        var options = Options(o => o.Network = "10.0.5.8/31");

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Equal(new[] { "10.0.5.8", "10.0.5.9" }, ips);
    }

    [Fact]
    public void Slash32_YieldsSingleAddress()
    {
        var options = Options(o => o.Network = "10.0.5.9/32");

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Single(ips);
        Assert.Equal("10.0.5.9", ips[0]);
    }

    [Fact]
    public void PlainIpWithPrefixLength_EquivalentToCidr()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.0";
            o.PrefixLength = 24;
        });

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Equal(255, ips.Count); // .1 ~ .255
        Assert.Contains("10.0.5.255", ips);
    }

    [Fact]
    public void ExceedingMaxScanAddresses_Throws()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.0/24";
            o.MaxScanAddresses = 16;
        });

        var ex = Assert.Throws<InvalidOperationException>(() => new RdpTargetCalculator().Calculate(options));
        Assert.Contains("MaxScanAddresses", ex.Message);
    }

    [Fact]
    public void MultipleExclusions_OrderDoesNotMatter()
    {
        var options = Options(o =>
        {
            o.Network = "10.0.5.0/24";
            o.ExcludedAddresses = new List<string> { "10.0.5.200", "10.0.5.88" };
        });

        var ips = Ips(new RdpTargetCalculator().Calculate(options));
        Assert.Equal(253, ips.Count);
        Assert.DoesNotContain("10.0.5.200", ips);
    }

    private static uint ToUInt32(string ip)
    {
        var bytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
}
