using System.Net;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Models;

namespace RdpSniffer.Tests;

// ---------- Fake TCP connection implementations ----------

internal sealed class FakeRdpConnection : IRdpConnection
{
    private readonly byte[]? _readData;
    private readonly Func<CancellationToken, ValueTask<int>>? _readBehavior;

    public FakeRdpConnection(byte[]? readData = null) => _readData = readData;

    public FakeRdpConnection(Func<CancellationToken, ValueTask<int>> readBehavior) => _readBehavior = readBehavior;

    public byte[]? Written { get; private set; }
    public bool Disposed { get; private set; }

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (_readBehavior is not null)
        {
            return _readBehavior(cancellationToken);
        }

        if (_readData is null || _readData.Length == 0)
        {
            return ValueTask.FromResult(0);
        }

        ((ReadOnlySpan<byte>)_readData).CopyTo(buffer.Span);
        return ValueTask.FromResult(_readData.Length);
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        Written = data.ToArray();
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        Disposed = true;
        return ValueTask.CompletedTask;
    }
}

internal sealed class FakeRdpConnectionFactory : IRdpConnectionFactory
{
    public Exception? ExceptionToThrow { get; set; }
    public IRdpConnection? Connection { get; set; }
    public int Calls => Volatile.Read(ref _calls);
    public IPAddress? LastAddress { get; private set; }
    public int LastPort { get; private set; }
    public TimeSpan LastTimeout { get; private set; }
    private int _calls;

    public Task<IRdpConnection> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        LastAddress = address;
        LastPort = port;
        LastTimeout = timeout;

        if (ExceptionToThrow is not null)
        {
            throw ExceptionToThrow;
        }

        return Task.FromResult(Connection ?? throw new InvalidOperationException("FakeRdpConnectionFactory.Connection is not set"));
    }
}

// ---------- Fake MSTSC login client implementations ----------

internal sealed class FakeMstscLoginClient : IMstscLoginClient
{
    public Func<MstscLoginRequest, CancellationToken, MstscLoginResult>? Handler { get; set; }

    public MstscLoginRequest? LastRequest { get; private set; }
    public bool Disposed { get; private set; }

    public Task<MstscLoginResult> LoginAsync(MstscLoginRequest request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        var result = Handler is null
            ? MstscLoginResult.Ok()
            : Handler(request, cancellationToken);
        return Task.FromResult(result);
    }

    public ValueTask DisposeAsync()
    {
        Disposed = true;
        return ValueTask.CompletedTask;
    }
}

internal sealed class FakeMstscLoginClientFactory : IMstscLoginClientFactory
{
    public Func<MstscLoginRequest, CancellationToken, MstscLoginResult>? Handler { get; set; }
    public Exception? CreateException { get; set; }
    public int Created => Volatile.Read(ref _created);
    public FakeMstscLoginClient? LastClient { get; private set; }
    private int _created;

    public IMstscLoginClient Create()
    {
        Interlocked.Increment(ref _created);
        if (CreateException is not null)
        {
            throw CreateException;
        }

        var client = new FakeMstscLoginClient { Handler = Handler };
        LastClient = client;
        return client;
    }
}

// ---------- Fake certificate name provider ----------

internal sealed class FakeCertificateNameProvider : IRdpCertificateNameProvider
{
    public Func<ProbeTarget, int, CancellationToken, Task<string?>>? Handler { get; set; }

    public string? Result { get; set; }

    public int Calls => Volatile.Read(ref _calls);
    public ProbeTarget? LastTarget { get; private set; }
    public int LastPort { get; private set; }
    private int _calls;

    public Task<string?> GetCertificateNameAsync(ProbeTarget target, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        LastTarget = target;
        LastPort = port;
        if (Handler is not null)
        {
            return Handler(target, port, cancellationToken);
        }

        return Task.FromResult(Result);
    }
}

// ---------- Fake probe (concurrency tracking + programmable behavior) ----------

internal sealed class FakeProbe : IRdpProbe
{
    public string Name => "FakeProbe";

    public Func<ProbeTarget, CancellationToken, Task<RdpProbeResult>>? Handler { get; set; }

    public int Calls => Volatile.Read(ref _calls);
    public int MaxConcurrent => Volatile.Read(ref _maxConcurrent);
    private int _calls;
    private int _maxConcurrent;
    private int _active;

    public async Task<RdpProbeResult> ProbeAsync(ProbeTarget target, CancellationToken cancellationToken)
    {
        var current = Interlocked.Increment(ref _active);
        try
        {
            while (true)
            {
                var observed = Volatile.Read(ref _maxConcurrent);
                if (current <= observed
                    || Interlocked.CompareExchange(ref _maxConcurrent, current, observed) == observed)
                {
                    break;
                }
            }

            Interlocked.Increment(ref _calls);

            if (Handler is not null)
            {
                return await Handler(target, cancellationToken);
            }

            return RdpProbeResult.Create(target, RdpProbeState.PortOpen);
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }
}
