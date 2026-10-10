using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpSniffer.Core.Abstractions;
using RdpSniffer.Core.Detection;
using RdpSniffer.Core.Options;
using RdpSniffer.Core.Reporting;
using RdpSniffer.Probes.CredSsp;
using RdpSniffer.Probes.Mstsc;
using RdpSniffer.Probes.Tcp;
using RdpSniffer.Service;
using RdpSniffer.Service.Composition;

var builder = Host.CreateApplicationBuilder(args);

// ---------- Configuration ----------
// All configuration is centralized in the "RdpDetection" node of appsettings.json;
// environment variables can override it, e.g. RdpDetection__Credentials__Password=xxx.
builder.Services
    .AddOptions<RdpDetectionOptions>()
    .Bind(builder.Configuration.GetSection(RdpDetectionOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<RdpDetectionOptions>, RdpDetectionOptionsValidator>();

// ---------- Infrastructure ----------
builder.Services.AddSingleton(TimeProvider.System);

// ---------- Probes ----------
builder.Services.AddSingleton<TcpRdpConnectionFactory>();
builder.Services.AddSingleton<IRdpConnectionFactory>(sp => sp.GetRequiredService<TcpRdpConnectionFactory>());
builder.Services.AddSingleton<IRdpCertificateNameProvider, TlsCertificateNameProvider>();
builder.Services.AddSingleton<TcpRdpProbe>();
builder.Services.AddSingleton<MstscLoginProbe>();
builder.Services.AddSingleton<ComMstscLoginClientFactory>();
builder.Services.AddSingleton<CredSspLoginClientFactory>();
// Choose the login client used by the login-verification stage (Auto: MSTSC ActiveX when available,
// otherwise the pure-protocol CredSSP/NLA client — no ActiveX component required).
builder.Services.AddSingleton<IMstscLoginClientFactory>(sp => MstscLoginClientComposition.Create(sp));
// Two-stage probe for VerifyCredentials=true: availability check first (kept/output), then full login verification
// on endpoints confirmed open. Wired explicitly to avoid the recursive IRdpProbe (composition-root) registration.
builder.Services.AddSingleton<VerifyCredentialsProbe>(sp => new VerifyCredentialsProbe(
    sp.GetRequiredService<TcpRdpProbe>(),
    sp.GetRequiredService<MstscLoginProbe>(),
    sp.GetRequiredService<ILogger<VerifyCredentialsProbe>>()));
// Select the final probe (port probing / two-stage verification) based on configuration + platform.
builder.Services.AddSingleton<IRdpProbe>(RdpProbeComposition.Create);

// ---------- Scan orchestration and report ----------
builder.Services.AddSingleton<RdpTargetCalculator>();
builder.Services.AddSingleton<RdpScanRunner>();
builder.Services.AddSingleton<IReportWriter, JsonReportWriter>();

// ---------- Hosted service ----------
builder.Services.AddHostedService<RdpScanWorker>();

var host = builder.Build();

await host.RunAsync();
