using System.Net;

namespace RdpSniffer.Core.Abstractions;

/// <summary>Low-level connection factory: separates "how to establish a TCP connection" from probe logic, allowing tests to inject fakes.</summary>
public interface IRdpConnectionFactory
{
    Task<IRdpConnection> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Minimal stream-like connection abstraction exposed to probe logic (read/write + dispose).</summary>
public interface IRdpConnection : IAsyncDisposable
{
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);
    ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken);
}

/// <summary>Connection failure category, used to generate friendly messages.</summary>
public enum RdpConnectionErrorKind
{
    Timeout,
    Refused,
    HostUnreachable,
    Other,
}

/// <summary>Exception thrown when a connection fails; carries the failure category.</summary>
public sealed class RdpConnectionException : Exception
{
    public RdpConnectionErrorKind Kind { get; }

    public RdpConnectionException(RdpConnectionErrorKind kind, string message, Exception? inner = null)
        : base(message, inner)
    {
        Kind = kind;
    }
}
