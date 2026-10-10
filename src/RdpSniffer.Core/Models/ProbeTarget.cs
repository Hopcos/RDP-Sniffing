using System.Net;
using System.Text.Json.Serialization;

namespace RdpSniffer.Core.Models;

/// <summary>A probe target (a single IPv4 address).</summary>
public sealed record ProbeTarget(
    [property: JsonIgnore] IPAddress Address)
{
    /// <summary>String form of the IP, used for JSON serialization and log display.</summary>
    public string Ip => Address.ToString();

    public static ProbeTarget Create(IPAddress address) => new(address);
}
