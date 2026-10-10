using RdpSniffer.Probes.Tcp;
using Xunit;

namespace RdpSniffer.Tests;

public class RdpBannerParserTests
{
    [Fact]
    public void EmptyResponse_ReturnsNone()
    {
        Assert.Equal(RdpServerResponseKind.None, RdpBannerParser.Classify(ReadOnlySpan<byte>.Empty));
    }

    [Theory]
    [InlineData(0x03, RdpServerResponseKind.X224ConnectionConfirm)]
    [InlineData(0x16, RdpServerResponseKind.TlsHandshake)]
    [InlineData(0x01, RdpServerResponseKind.Unknown)]
    public void ClassifiesByFirstByte(byte firstByte, RdpServerResponseKind expected)
    {
        var response = new byte[] { firstByte, 0x00, 0x00, 0x0D };
        Assert.Equal(expected, RdpBannerParser.Classify(response));
    }

    [Fact]
    public void ConnectionRequestPayload_IsValidTpktX224Cr()
    {
        var payload = RdpBannerParser.ConnectionRequestPayload.ToArray();

        Assert.Equal(19, payload.Length);
        Assert.Equal(0x03, payload[0]);   // TPKT version
        Assert.Equal(0x00, payload[1]);
        Assert.Equal(0x00, payload[2]);
        Assert.Equal(0x13, payload[3]);   // total length 19
        Assert.Equal(0xE0, payload[5]);   // X.224 connection request code
    }
}
