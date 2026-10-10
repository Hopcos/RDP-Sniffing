using RdpSniffer.Core.Abstractions;

namespace RdpSniffer.Probes.Mstsc;

/// <summary>
/// MSTSC login client factory: creates one independent <see cref="ComMstscLoginClient"/> per target.
/// This type only touches Windows Forms / COM when actually used, so it is safe on non-Windows platforms.
/// </summary>
public sealed class ComMstscLoginClientFactory : IMstscLoginClientFactory
{
    public IMstscLoginClient Create() => new ComMstscLoginClient();
}

/// <summary>
/// Full login verification implementation built on the system Remote Desktop ActiveX component
/// (MsRdpClient*, same origin as mstsc.exe). Each login request runs on a dedicated STA thread with a
/// hidden window and a message pump; the outcome is decided by "event binding (preferred when successfully
/// bound) + polling the Connected property as a fallback".
/// </summary>
public sealed class ComMstscLoginClient : IMstscLoginClient
{
    public Task<MstscLoginResult> LoginAsync(MstscLoginRequest request, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(MstscLoginResult.Fail(
                MstscLoginFailureKind.ProtocolError,
                description: "MSTSC login verification is only supported on Windows (current platform is not supported)"));
        }

        var tcs = new TaskCompletionSource<MstscLoginResult>(TaskCreationOptions.RunContinuationsAsynchronously);

        var thread = new Thread(() =>
        {
            try
            {
                var result = MstscSession.Run(request, cancellationToken);
                tcs.TrySetResult(result);
            }
            catch (OperationCanceledException ex)
            {
                tcs.TrySetException(ex);
            }
            catch (Exception ex)
            {
                tcs.TrySetResult(MstscLoginResult.Fail(
                    MstscLoginFailureKind.ProtocolError,
                    description: ex.Message));
            }
        })
        {
            IsBackground = true,
            Name = $"RdpLogin-{request.Host}",
        };

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        return tcs.Task;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
