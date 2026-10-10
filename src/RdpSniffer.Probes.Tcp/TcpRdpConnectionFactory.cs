using System.Net;
using System.Net.Sockets;
using RdpSniffer.Core.Abstractions;

namespace RdpSniffer.Probes.Tcp;

/// <summary>
/// Real connection factory based on <see cref="TcpClient"/>.
/// Timeout is implemented via CTS.CancelAfter: on expiry it is converted to an
/// <see cref="RdpConnectionException"/> (Timeout); an active user cancellation propagates
/// OperationCanceledException as-is.
/// </summary>
public sealed class TcpRdpConnectionFactory : IRdpConnectionFactory
{
    public async Task<IRdpConnection> ConnectAsync(
        IPAddress address,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        var client = new TcpClient { NoDelay = true };
        try
        {
            await client.ConnectAsync(address, port, timeoutCts.Token).ConfigureAwait(false);
            return new TcpRdpConnection(client);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            client.Dispose();
            throw new RdpConnectionException(
                RdpConnectionErrorKind.Timeout,
                $"Connection to {address}:{port} timed out ({timeout.TotalSeconds:0.#} seconds)");
        }
        catch (SocketException ex)
        {
            client.Dispose();
            var kind = ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => RdpConnectionErrorKind.Refused,
                SocketError.HostUnreachable or SocketError.NetworkUnreachable
                    or SocketError.HostNotFound => RdpConnectionErrorKind.HostUnreachable,
                _ => RdpConnectionErrorKind.Other,
            };
            throw new RdpConnectionException(
                kind,
                $"Connection to {address}:{port} failed ({ex.SocketErrorCode})",
                ex);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }
}

/// <summary>Minimal wrapper over <see cref="NetworkStream"/>.</summary>
internal sealed class TcpRdpConnection : IRdpConnection
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;

    public TcpRdpConnection(TcpClient client)
    {
        _client = client;
        _stream = client.GetStream();
    }

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        => _stream.ReadAsync(buffer, cancellationToken);

    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        => _stream.WriteAsync(data, cancellationToken);

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return ValueTask.CompletedTask;
    }
}
