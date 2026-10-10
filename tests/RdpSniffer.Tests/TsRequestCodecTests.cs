using RdpSniffer.Probes.CredSsp;
using Xunit;

namespace RdpSniffer.Tests;

public class TsRequestCodecTests
{
    [Fact]
    public void EncodeWithNegoToken_RoundTrips()
    {
        var token = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var frame = TsRequestCodec.EncodeWithNegoToken(token);
        var info = TsRequestCodec.Decode(frame);

        Assert.Equal(2, info.Version);
        Assert.Single(info.NegoTokens);
        Assert.Equal(token, info.NegoTokens[0]);
        Assert.Null(info.PubKeyAuth);
        Assert.Null(info.ErrorCode);
    }

    [Fact]
    public void EncodeWithNegoToken_LargeTokenUsesLongFormLength()
    {
        var token = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();

        var frame = TsRequestCodec.EncodeWithNegoToken(token);
        var info = TsRequestCodec.Decode(frame);

        Assert.Equal(token, info.NegoTokens.Single());
    }

    [Fact]
    public void Decode_ServerMessageWithPubKeyAuth()
    {
        // TSRequest ::= SEQUENCE { version [0] INTEGER 2, negoTokens [1] <data>, pubKeyAuth [3] <bytes> }
        var negoData = Tlv(0x30, Tlv(0x30, Tlv(0x80, new byte[] { 0xAA, 0xBB })));
        var payload = Concat(
            Tlv(0xA0, new byte[] { 0x02, 0x01, 0x02 }),
            Tlv(0xA1, negoData),
            Tlv(0xA3, new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }));
        var frame = Tlv(0x30, payload);

        var info = TsRequestCodec.Decode(frame);

        Assert.Equal(2, info.Version);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, info.NegoTokens.Single());
        Assert.Equal(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }, info.PubKeyAuth);
    }

    [Fact]
    public void Decode_ServerMessageWithErrorCode()
    {
        var payload = Concat(
            Tlv(0xA0, new byte[] { 0x02, 0x01, 0x01 }),
            Tlv(0xA4, new byte[] { 0x02, 0x01, 0x05 }));
        var frame = Tlv(0x30, payload);

        var info = TsRequestCodec.Decode(frame);

        Assert.Equal(1, info.Version);
        Assert.Equal(0x05, info.ErrorCode);
        Assert.Empty(info.NegoTokens);
    }

    [Fact]
    public void Decode_Garbage_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => TsRequestCodec.Decode(new byte[] { 0x01, 0x02, 0x03 }));
    }

    private static byte[] Tlv(byte tag, byte[] content)
    {
        var result = new byte[2 + content.Length];
        result[0] = tag;
        result[1] = (byte)content.Length;
        content.CopyTo(result, 2);
        return result;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }
}
