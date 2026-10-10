using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using RdpSniffer.Core.Abstractions;

namespace RdpSniffer.Probes.CredSsp;

public sealed class CredSspLoginClientFactory : IMstscLoginClientFactory
{
    public IMstscLoginClient Create() => new CredSspLoginClient();
}

/// <summary>
/// Protocol-based (CredSSP / Network Level Authentication) login-verification client.
/// Performs the wire-level RDP NLA handshake without any RDP ActiveX component:
///
///   TCP connect → X.224 connection confirm (protocol negotiation) → TLS → CredSSP (SPNEGO/NTLM).
///
/// The NTLM exchange runs over the built-in Windows SSPI via <see cref="NegotiateAuthentication"/>:
/// NLA stands for "authenticate first, connect second", so a successful NTLM authentication proves
/// that the supplied user name and password are valid — no interactive desktop session is needed.
///
/// Requirements / limitations:
///   - The target server must have NLA enabled (the Windows RDP default). Servers with NLA disabled
///     use the legacy security (RC4 logon) layer, which this client does not implement.
///   - NTLM via SSPI requires Windows (same platform constraint as the MSTSC ActiveX component).
/// </summary>
public sealed class CredSspLoginClient : IMstscLoginClient
{
    // X.224 Connection Request (TPKT + X.224 CR + RDP Negotiation Request).
    // The 4 trailing bytes request PROTOCOL_RDP | PROTOCOL_SSL (0x03).
    private static readonly byte[] ConnectionRequestPayload =
    {
        0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
    };

    private const int MaxTlsBufferSize = 16 * 1024;

    public async Task<MstscLoginResult> LoginAsync(MstscLoginRequest request, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return MstscLoginResult.Fail(
                MstscLoginFailureKind.ProtocolError,
                description: "Protocol-based (CredSSP/NLA) login verification uses the Windows SSPI for NTLM and is only supported on Windows.");
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(request.Timeout);

        try
        {
            using var tcp = await ConnectAsync(request, timeoutCts.Token).ConfigureAwait(false);
            using var stream = tcp.GetStream();

            // 1) X.224 connection request/confirm — checks NLA/TLS negotiation before anything else.
            if (!await IsNlaNegotiatedAsync(stream, timeoutCts.Token).ConfigureAwait(false))
            {
                return MstscLoginResult.Fail(
                    MstscLoginFailureKind.ProtocolError,
                    description: "The RDP server does not support NLA (network level authentication); credential verification over the protocol is not possible against legacy (non-NLA) servers. Enable NLA on the server or use the MSTSC client.");
            }

            // 2) TLS — the CredSSP transport.
            using var ssl = await OpenTlsAsync(stream, request.Host, timeoutCts.Token).ConfigureAwait(false);

            // 3) CredSSP SPNEGO/NTLM exchange — a successful NTLM authentication proves the credentials.
            return await CredSspExchangeAsync(ssl, request, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return MstscLoginResult.Fail(
                MstscLoginFailureKind.Timeout,
                description: $"Login verification timed out ({request.Timeout.TotalSeconds:0.#} seconds); the server is reachable but did not complete the NLA exchange.");
        }
        catch (SocketException ex)
        {
            return MstscLoginResult.Fail(
                MstscLoginFailureKind.ConnectionError,
                description: $"Connection to {request.Host}:{request.Port} failed ({ex.SocketErrorCode}).");
        }
        catch (System.Security.Authentication.AuthenticationException ex)
        {
            return MstscLoginResult.Fail(
                MstscLoginFailureKind.ProtocolError,
                description: $"TLS/CredSSP negotiation failed: {FlattenMessage(ex)}");
        }
        catch (Exception ex)
        {
            return MstscLoginResult.Fail(
                MstscLoginFailureKind.ProtocolError,
                description: ex.Message);
        }
    }

    private static string FlattenMessage(Exception ex)
    {
        var deepest = ex;
        while (deepest.InnerException is not null)
        {
            deepest = deepest.InnerException;
        }

        return deepest == ex ? ex.Message : $"{ex.Message} ({deepest.Message})";
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private static async Task<TcpClient> ConnectAsync(MstscLoginRequest request, CancellationToken cancellationToken)
    {
        var address = IPAddress.Parse(request.Host);
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(address, request.Port, cancellationToken).ConfigureAwait(false);
            return tcp;
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Sends the X.224 connection request and inspects the connection confirm for the RDP
    /// negotiation response. Returns true when the server selected a TLS-capable protocol
    /// (SSL, HYBRID, ...), i.e. NLA can be attempted.
    /// </summary>
    private static async Task<bool> IsNlaNegotiatedAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(ConnectionRequestPayload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Read one complete TPKT frame (4-byte header carries the total length).
        var tpkt = new byte[4];
        var headerRead = await ReadAtLeastAsync(stream, tpkt, tpkt.Length, cancellationToken).ConfigureAwait(false);
        if (headerRead < 4 || tpkt[0] != 0x03 || tpkt[1] != 0x00)
        {
            return false;
        }

        var frameLength = (tpkt[2] << 8) | tpkt[3];
        if (frameLength < 11 || frameLength > 512)
        {
            return false;
        }

        var response = new byte[frameLength];
        tpkt.CopyTo(response, 0);
        var payloadRead = await ReadAtLeastAsync(stream, response.AsMemory(4), frameLength - 4, cancellationToken).ConfigureAwait(false);
        if (payloadRead < frameLength - 4 || response[5] != 0xD0)
        {
            // Not a complete/sanely-formatted X.224 connection confirm → cannot negotiate NLA.
            return false;
        }

        // RDP Negotiation Response (MS-RDPBCGR 2.2.1.2): a 19-byte connection confirm carries an 8-byte
        // negotiation block whose last 4 bytes (little-endian) are selectedProtocol. The leading
        // type/flags bytes are not validated strictly — some RDP implementations set flag bits there.
        if (frameLength < 19)
        {
            // The server replied without a protocol negotiation block → legacy RDP security, no NLA.
            return false;
        }

        var selectedProtocol = response[15] | (response[16] << 8) | (response[17] << 16) | (response[18] << 24);
        return selectedProtocol != 0; // PROTOCOL_RDP (0) = legacy security; anything else is TLS-based.
    }

    private static async Task<SslStream> OpenTlsAsync(Stream stream, string host, CancellationToken cancellationToken)
    {
        var ssl = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);
        try
        {
#pragma warning disable SYSLIB0039 // TLS 1.0/1.1 are intentionally offered for legacy RDP servers
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12,
                AllowRenegotiation = false,
            };
#pragma warning restore SYSLIB0039

            await ssl.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
            return ssl;
        }
        catch
        {
            ssl.Dispose();
            throw;
        }
    }

    private static async Task<MstscLoginResult> CredSspExchangeAsync(
        SslStream ssl,
        MstscLoginRequest request,
        CancellationToken cancellationToken)
    {
        using var auth = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions
        {
            Package = "Negotiate",
            Credential = new NetworkCredential(request.UserName, request.Password, request.Domain),
            TargetName = $"TERMSRV/{request.Host}",
        });

        // --- Stage 1/2: client NTLM Negotiate ______
        var negotiateBlob = auth.GetOutgoingBlob(ReadOnlySpan<byte>.Empty, out NegotiateAuthenticationStatusCode status);
        if (negotiateBlob is null || status != NegotiateAuthenticationStatusCode.ContinueNeeded)
        {
            return ProtocolFailure($"SPNEGO negotiation could not be started ({status}).");
        }

        await WriteTsRequestAsync(ssl, negotiateBlob, cancellationToken).ConfigureAwait(false);

        // --- Server NTLM Challenge ______
        var challengeFrame = await ReadTsRequestAsync(ssl, cancellationToken).ConfigureAwait(false);
        if (challengeFrame is null)
        {
            return Rejected("the server closed the connection before the NTLM challenge (credentials may be wrong).");
        }

        var challengeReply = TsRequestCodec.Decode(challengeFrame);
        if (challengeReply.ErrorCode is not null)
        {
            return Rejected($"the server rejected the authentication attempt (CredSSP error 0x{challengeReply.ErrorCode.Value:X}).");
        }

        var challengeToken = challengeReply.NegoTokens.FirstOrDefault();
        if (challengeToken is null)
        {
            return ProtocolFailure("the server returned a TSRequest without an NTLM challenge token.");
        }

        var authenticateBlob = auth.GetOutgoingBlob(challengeToken, out status);
        if (authenticateBlob is null)
        {
            return ProtocolFailure($"NTLM authentication could not be completed ({status}).");
        }

        await WriteTsRequestAsync(ssl, authenticateBlob, cancellationToken).ConfigureAwait(false);

        // --- Outcome: a correct user name/password is accepted at the NTLM stage; the server then
        // continues the CredSSP exchange (it sends the next TSRequest, e.g. its pubKeyAuth).
        // A wrong password makes the server tear down the connection right away (read returns 0).
        byte[]? outcome = null;
        try
        {
            outcome = await ReadTsRequestAsync(ssl, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException ex) when (ex.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset or SocketError.ConnectionAborted })
        {
            return Rejected("the connection was reset right after the NTLM authenticate message (wrong user name or password).");
        }

        if (outcome is null)
        {
            return Rejected("the connection was closed right after the NTLM authenticate message (wrong user name or password).");
        }

        // The server accepted the NTLM authentication and continues the handshake → credentials are valid.
        return MstscLoginResult.Ok();
    }

    private static MstscLoginResult Rejected(string context)
        => MstscLoginResult.Fail(MstscLoginFailureKind.AuthenticationError, description: $"Login was rejected — {context}");

    private static MstscLoginResult ProtocolFailure(string message)
        => MstscLoginResult.Fail(MstscLoginFailureKind.ProtocolError, description: message);

    private static async Task WriteTsRequestAsync(SslStream ssl, byte[] spnegoToken, CancellationToken cancellationToken)
    {
        var frame = TsRequestCodec.EncodeWithNegoToken(spnegoToken);
        await ssl.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await ssl.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one complete TSRequest from the TLS stream; null when the peer closed the connection (EOF).
    /// </summary>
    private static async Task<byte[]?> ReadTsRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        var headerRead = await ReadAtLeastAsync(stream, header, 2, cancellationToken).ConfigureAwait(false);
        if (headerRead < 2)
        {
            return null;
        }

        var first = header[1];
        int lengthLength;
        if ((first & 0x80) == 0)
        {
            lengthLength = 0;
        }
        else
        {
            lengthLength = first & 0x7F;
            if (lengthLength is 0 or > 4)
            {
                throw new InvalidDataException($"Unsupported TSRequest length encoding (0x{first:X2}).");
            }
        }

        var lengthBytes = lengthLength == 0 ? Array.Empty<byte>() : new byte[lengthLength];
        if (lengthBytes.Length > 0)
        {
            var lgth = await ReadAtLeastAsync(stream, lengthBytes, lengthBytes.Length, cancellationToken).ConfigureAwait(false);
            if (lgth < lengthBytes.Length)
            {
                return null;
            }
        }

        var contentLength = first & 0x7F;
        if (lengthLength > 0)
        {
            contentLength = 0;
            foreach (var b in lengthBytes)
            {
                contentLength = (contentLength << 8) | b;
            }
        }

        if (contentLength <= 0 || contentLength > MaxTlsBufferSize)
        {
            throw new InvalidDataException($"Invalid TSRequest content length {contentLength}.");
        }

        var content = new byte[contentLength];
        var contentRead = await ReadAtLeastAsync(stream, content, content.Length, cancellationToken).ConfigureAwait(false);
        if (contentRead < content.Length)
        {
            return null;
        }

        var frame = new byte[2 + lengthLength + contentLength];
        header.CopyTo(frame, 0);
        lengthBytes.CopyTo(frame, 2);
        content.CopyTo(frame, 2 + lengthLength);
        return frame;
    }

    private static async Task<int> ReadAtLeastAsync(Stream stream, Memory<byte> buffer, int minimum, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < minimum)
        {
            var read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }
}
