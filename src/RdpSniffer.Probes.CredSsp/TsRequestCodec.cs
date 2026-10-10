namespace RdpSniffer.Probes.CredSsp;

/// <summary>
/// Minimal BER/DER codec for the CredSSP TSRequest message (MS-CSSP 2.2.1):
///
///   TSRequest ::= SEQUENCE {
///       version     [0] INTEGER (1..2),
///       negoTokens  [1] NegoData OPTIONAL,
///       authInfo    [2] OCTET STRING OPTIONAL,
///       pubKeyAuth  [3] OCTET STRING OPTIONAL,
///       errorCode   [4] INTEGER OPTIONAL,
///       clientNonce [5] OCTET STRING OPTIONAL
///   }
///
///   NegoData     ::= SEQUENCE OF NegoDataItem
///   NegoDataItem ::= SEQUENCE { negoToken [0] OCTET STRING }
///
/// Only the members used by this client are implemented.
/// </summary>
public static class TsRequestCodec
{
    public sealed record TsRequestInfo(
        int Version,
        IReadOnlyList<byte[]> NegoTokens,
        byte[]? PubKeyAuth,
        int? ErrorCode);

    /// <summary>Encodes a TSRequest containing a single SPNEGO negotiation token (client message).</summary>
    public static byte[] EncodeWithNegoToken(byte[] spnegoToken)
    {
        // NegoDataItem ::= SEQUENCE { negoToken [0] OCTET STRING }
        var item = Tlv(0x30, Tlv(0x80, spnegoToken));
        // NegoData ::= SEQUENCE OF NegoDataItem
        var negoData = Tlv(0x30, item);
        // version [0] INTEGER 2
        var version = Tlv(0xA0, new byte[] { 0x02, 0x01, 0x02 });
        // negoTokens [1] explicit (constructed) wrapping the NegoData sequence
        var negoTokens = Tlv(0xA1, negoData);
        return Tlv(0x30, Concat(version, negoTokens));
    }

    public static TsRequestInfo Decode(ReadOnlySpan<byte> data)
    {
        var rootOffset = 0;
        var (rootTag, rootContent) = ReadTlv(data, ref rootOffset);
        if (rootTag != 0x30)
        {
            throw new FormatException($"Expected TSRequest SEQUENCE (0x30), got 0x{rootTag:X2}");
        }

        var version = 0;
        var tokens = new List<byte[]>();
        byte[]? pubKeyAuth = null;
        int? errorCode = null;

        var offset = 0;
        while (offset < rootContent.Length)
        {
            var (tag, fieldContent) = ReadTlv(rootContent, ref offset);
            switch (tag)
            {
                case 0xA0: // version [0] INTEGER
                    var intOffset = 0;
                    var (intTag, intBytes) = ReadTlv(fieldContent, ref intOffset);
                    if (intTag == 0x02)
                    {
                        version = ParseInteger(intBytes);
                    }
                    break;

                case 0xA1: // negoTokens [1] NegoData
                    var seqOffset = 0;
                    var (seqTag, seqContent) = ReadTlv(fieldContent, ref seqOffset);
                    if (seqTag == 0x30)
                    {
                        var itemOffset = 0;
                        while (itemOffset < seqContent.Length)
                        {
                            var (itemTag, itemContent) = ReadTlv(seqContent, ref itemOffset);
                            if (itemTag == 0x30)
                            {
                                var tokenOffset = 0;
                                var (tokenTag, token) = ReadTlv(itemContent, ref tokenOffset);
                                if (tokenTag == 0x80)
                                {
                                    tokens.Add(token);
                                }
                            }
                        }
                    }
                    break;

                case 0xA3: // pubKeyAuth [3] OCTET STRING
                    pubKeyAuth = fieldContent;
                    break;

                case 0xA4: // errorCode [4] INTEGER
                    var errOffset = 0;
                    var (errTag, errBytes) = ReadTlv(fieldContent, ref errOffset);
                    if (errTag == 0x02)
                    {
                        errorCode = ParseInteger(errBytes);
                    }
                    break;
            }
        }

        return new TsRequestInfo(version, tokens, pubKeyAuth, errorCode);
    }

    private static byte[] Tlv(byte tag, byte[] content)
    {
        if (content.Length < 0x80)
        {
            var result = new byte[2 + content.Length];
            result[0] = tag;
            result[1] = (byte)content.Length;
            content.CopyTo(result, 2);
            return result;
        }

        if (content.Length <= 0xFF)
        {
            var result = new byte[3 + content.Length];
            result[0] = tag;
            result[1] = 0x81;
            result[2] = (byte)content.Length;
            content.CopyTo(result, 3);
            return result;
        }

        var longResult = new byte[4 + content.Length];
        longResult[0] = tag;
        longResult[1] = 0x82;
        longResult[2] = (byte)(content.Length >> 8);
        longResult[3] = (byte)content.Length;
        content.CopyTo(longResult, 4);
        return longResult;
    }

    private static (byte Tag, byte[] Content) ReadTlv(ReadOnlySpan<byte> data, ref int offset)
    {
        if (offset >= data.Length)
        {
            throw new FormatException("Truncated TLV header");
        }

        var tag = data[offset++];
        if (offset >= data.Length)
        {
            throw new FormatException("Truncated TLV length");
        }

        var first = data[offset++];
        int length;
        if ((first & 0x80) == 0)
        {
            length = first;
        }
        else
        {
            var count = first & 0x7F;
            if (count == 0 || count > 4)
            {
                throw new FormatException("Unsupported long-form TLV length");
            }

            if (offset + count > data.Length)
            {
                throw new FormatException("Truncated long-form TLV length");
            }

            length = 0;
            for (var i = 0; i < count; i++)
            {
                length = (length << 8) | data[offset++];
            }
        }

        if (offset + length > data.Length)
        {
            throw new FormatException("Truncated TLV content");
        }

        var content = data.Slice(offset, length).ToArray();
        offset += length;
        return (tag, content);
    }

    private static int ParseInteger(byte[] bytes)
    {
        var value = 0;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
        }

        return value;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var result = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }
}
