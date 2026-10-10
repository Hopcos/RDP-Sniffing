namespace RdpSniffer.Probes.Tcp;

/// <summary>Classification of the server handshake response.</summary>
public enum RdpServerResponseKind
{
    /// <summary>No data received (connection closed or silent).</summary>
    None,

    /// <summary>Received a TPKT/X.224 frame (first byte 0x03); usually an X.224 connection confirm.</summary>
    X224ConnectionConfirm,

    /// <summary>Received a TLS record (first byte 0x16); usually direct TLS negotiation when the server enforces NLA.</summary>
    TlsHandshake,

    /// <summary>Received unrecognizable data.</summary>
    Unknown,
}

/// <summary>RDP handshake protocol parsing: decides whether the server response belongs to the RDP protocol family.</summary>
public static class RdpBannerParser
{
    /// <summary>
    /// Minimal X.224 Connection Request payload:
    ///   TPKT header(4) + X.224 CR(0x0E) + RDP negotiation header.
    /// Most RDP servers answer immediately with an X.224 connection confirm.
    /// </summary>
    public static ReadOnlyMemory<byte> ConnectionRequestPayload => new byte[]
    {
        0x03, 0x00, 0x00, 0x13, // TPKT: version 3, total length 19
        0x0E,                   // X.224: connection request, LI=14 (14 bytes follow)
        0xE0, 0x00, 0x00, 0x00, // code + destination reference(2) + source reference high byte
        0x00, 0x00,             // source reference low byte + class
        0x01, 0x00, 0x08, 0x00, // RDP negotiation header: type 1 (request), flags 0, length 8
        0x03, 0x00, 0x00, 0x00, // requested RDP version 3
    };

    public static RdpServerResponseKind Classify(ReadOnlySpan<byte> response)
    {
        if (response.Length == 0)
        {
            return RdpServerResponseKind.None;
        }

        return response[0] switch
        {
            0x03 => RdpServerResponseKind.X224ConnectionConfirm,
            0x16 => RdpServerResponseKind.TlsHandshake,
            _ => RdpServerResponseKind.Unknown,
        };
    }
}
