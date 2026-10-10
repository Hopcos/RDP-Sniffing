using System.Reflection;
using System.Windows.Forms;
using RdpSniffer.Core.Abstractions;

namespace RdpSniffer.Probes.Mstsc;

/// <summary>
/// Hidden AxHost that hosts the Remote Desktop ActiveX control. AxHost provides the window and message
/// routing for the native COM control, which is the standard way to use MsRdpClient headless.
/// </summary>
internal sealed class RdpClientHost : AxHost
{
    public RdpClientHost(string clsid)
        : base(clsid)
    {
    }

    public new object? GetOcx() => base.GetOcx();
}

/// <summary>The full executor of one MSTSC login session.</summary>
internal static class MstscSession
{
    private static readonly string[] CandidateProgIds =
    {
        "MsRdpClient9NotSafeForScripting",
        "MsRdpClient8NotSafeForScripting",
        "MsRdpClient6NotSafeForScripting",
        "MsRdpClientNotSafeForScripting",
    };

    private static readonly string[] AdvancedSettingsPropertyNames =
    {
        "AdvancedSettings9",
        "AdvancedSettings8",
        "AdvancedSettings6",
        "AdvancedSettings5",
        "AdvancedSettings2",
        "AdvancedSettings1",
    };

    public static MstscLoginResult Run(MstscLoginRequest request, CancellationToken cancellationToken)
    {
        var controlType = ResolveControlType();
        if (controlType is null)
        {
            return MstscLoginResult.Fail(
                MstscLoginFailureKind.ProtocolError,
                description: "RDP ActiveX client component (MsRdpClient*) was not found; make sure the 'Remote Desktop Connection' component is installed.");
        }

        object? control = null;
        RdpClientHost? host = null;
        using var form = new Form
        {
            ShowInTaskbar = false,
            Opacity = 0,
            FormBorderStyle = FormBorderStyle.None,
            StartPosition = FormStartPosition.Manual,
            Location = new System.Drawing.Point(-32000, -32000),
            ClientSize = new System.Drawing.Size(640, 480),
        };

        try
        {
            host = new RdpClientHost(controlType.GUID.ToString("D"));
            form.Controls.Add(host);
            host.CreateControl();
            host.Visible = false;
            host.Dock = DockStyle.Fill;
            form.Show(); // Establishes the HWND and provides a message pump (driven later by DoEvents)

            control = host.GetOcx();
            if (control is null)
            {
                return MstscLoginResult.Fail(
                    MstscLoginFailureKind.ProtocolError,
                    description: "RDP ActiveX host created, but the control object could not be obtained.");
            }

            var sink = new SessionEventSink();
            TryAttachEvents(control, sink);
            Configure(control, request);

            if (!InvokeMethod(control, "Connect"))
            {
                return MstscLoginResult.Fail(
                    MstscLoginFailureKind.ProtocolError,
                    description: "Calling the RDP client Connect() failed (the component may not be installed correctly, or the process runs as a service account that cannot create a desktop).");
            }

            return PumpUntilDone(control, sink, request, cancellationToken);
        }
        finally
        {
            try
            {
                if (control is not null)
                {
                    InvokeMethod(control, "Disconnect");
                }
            }
            catch
            {
                // Ignore exceptions during cleanup
            }

            host?.Dispose();
        }
    }

    // ---------- Connection state pump ----------

    private static MstscLoginResult PumpUntilDone(
        object control,
        SessionEventSink sink,
        MstscLoginRequest request,
        CancellationToken cancellationToken)
    {
        var connectedProperty = control.GetType().GetProperty("Connected", BindingFlags.Instance | BindingFlags.Public);
        var deadline = DateTime.UtcNow + request.Timeout;
        var pollInterval = Math.Max(50, request.PollingIntervalMilliseconds);

        while (true)
        {
            Application.DoEvents();

            cancellationToken.ThrowIfCancellationRequested();

            // Event channel first (real client events), polling channel as a fallback.
            var connected = sink.ConnectedEventFired
                || sink.LoginCompleteFired
                || (connectedProperty?.GetValue(control) as bool? ?? false);

            if (connected)
            {
                return MstscLoginResult.Ok();
            }

            if (sink.LogonErrorCode.HasValue)
            {
                return MstscLoginResult.Fail(
                    MstscLoginFailureKind.AuthenticationError,
                    errorCode: sink.LogonErrorCode.Value.ToString("X8"),
                    description: sink.LogonErrorDescription ?? "Login rejected (user name or password may be wrong)");
            }

            if (sink.DisconnectedFired)
            {
                return MstscLoginResult.Fail(
                    MstscLoginFailureKind.ConnectionError,
                    errorCode: sink.DisconnectReason?.ToString(),
                    description: sink.DisconnectDescription ?? "Connection was closed before login completed");
            }

            if (DateTime.UtcNow >= deadline)
            {
                var extra = ReadDisconnectedText(control);
                return MstscLoginResult.Fail(
                    MstscLoginFailureKind.Timeout,
                    description: $"Login did not complete within {request.Timeout.TotalSeconds:0.#} seconds{extra}. Check credentials, network reachability and the server NLA settings.");
            }

            Thread.Sleep(pollInterval);
        }
    }

    // ---------- Configuration ----------

    private static void Configure(object control, MstscLoginRequest request)
    {
        SetProperty(control, "Server", request.Host);
        SetProperty(control, "UserName", request.UserName);

        if (!string.IsNullOrWhiteSpace(request.Domain))
        {
            SetProperty(control, "Domain", request.Domain);
        }

        var settings = GetAdvancedSettings(control);
        if (settings is not null)
        {
            SetProperty(settings, "ClearTextPassword", request.Password);
            SetProperty(settings, "EnableCredSspSupport", request.EnableCredSspSupport);
            SetProperty(settings, "AuthenticationLevel", request.AuthenticationLevel);
            SetProperty(settings, "PromptForCredentials", false);
        }
    }

    private static object? GetAdvancedSettings(object control)
    {
        foreach (var name in AdvancedSettingsPropertyNames)
        {
            var value = GetProperty(control, name);
            if (value is not null)
            {
                return value;
            }
        }

        return null;
    }

    // ---------- Event binding (best effort; polling serves as the fallback) ----------

    private static void TryAttachEvents(object control, SessionEventSink sink)
    {
        var sinkType = sink.GetType();
        var targetType = control.GetType();

        foreach (var eventName in new[] { "OnConnected", "OnLoginComplete", "OnLogonError", "OnDisconnected" })
        {
            try
            {
                var eventInfo = targetType.GetEvent(eventName, BindingFlags.Instance | BindingFlags.Public);
                if (eventInfo is null)
                {
                    continue;
                }

                var invoke = eventInfo.EventHandlerType!.GetMethod("Invoke");
                if (invoke is null)
                {
                    continue;
                }

                var parameterTypes = invoke.GetParameters().Select(p => p.ParameterType).ToArray();
                var handler = parameterTypes.Length == 0
                    ? sinkType.GetMethod(eventName, BindingFlags.Instance | BindingFlags.Public)
                    : sinkType.GetMethod(
                        eventName,
                        BindingFlags.Instance | BindingFlags.Public,
                        binder: null,
                        types: parameterTypes,
                        modifiers: null);

                if (handler is null)
                {
                    continue;
                }

                var @delegate = Delegate.CreateDelegate(eventInfo.EventHandlerType, sink, handler);
                eventInfo.AddEventHandler(control, @delegate);
            }
            catch
            {
                // Signature mismatches across ActiveX versions etc.; ignore and fall back to polling.
            }
        }
    }

    // ---------- Reflection helpers ----------

    private static Type? ResolveControlType()
    {
        foreach (var progId in CandidateProgIds)
        {
            try
            {
                var type = Type.GetTypeFromProgID(progId);
                if (type is not null)
                {
                    return type;
                }
            }
            catch
            {
                // Try the next ProgID
            }
        }

        return null;
    }

    private static void SetProperty(object instance, string name, object? value)
    {
        try
        {
            instance.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public)?.SetValue(instance, value);
        }
        catch
        {
            // Different ActiveX versions expose different property sets; ignore inaccessible properties.
        }
    }

    private static object? GetProperty(object instance, string name)
    {
        try
        {
            return instance.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public)?.GetValue(instance);
        }
        catch
        {
            return null;
        }
    }

    private static bool InvokeMethod(object instance, string name)
    {
        try
        {
            instance.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.Public)?.Invoke(instance, null);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ReadDisconnectedText(object control)
    {
        var value = GetProperty(control, "DisconnectedText");
        return value is string { Length: > 0 } text ? $" (disconnect info: {text})" : string.Empty;
    }
}

/// <summary>ActiveX event sink. Method signatures align with the _IMsTscAxEvents members in the TLB; binding is done by signature matching via reflection.</summary>
internal sealed class SessionEventSink
{
    public bool ConnectedEventFired { get; private set; }
    public bool LoginCompleteFired { get; private set; }
    public int? LogonErrorCode { get; private set; }
    public string? LogonErrorDescription { get; private set; }
    public bool DisconnectedFired { get; private set; }
    public int? DisconnectReason { get; private set; }
    public string? DisconnectDescription { get; private set; }

    public void OnConnected() => ConnectedEventFired = true;

    public void OnLoginComplete() => LoginCompleteFired = true;

    public void OnLogonError(int errorCode, string? description)
    {
        LogonErrorCode = errorCode;
        LogonErrorDescription = description;
    }

    public void OnLogonError(int errorCode)
    {
        LogonErrorCode = errorCode;
        LogonErrorDescription = $"Logon error code 0x{errorCode:X8}";
    }

    public void OnDisconnected(int reason, string? description)
    {
        DisconnectedFired = true;
        DisconnectReason = reason;
        DisconnectDescription = description;
    }

    public void OnDisconnected()
    {
        DisconnectedFired = true;
    }
}
