using System.Net;
using RdpSniffer.Core.Models;
using RdpSniffer.Core.Options;

namespace RdpSniffer.Core.Detection;

/// <summary>
/// Target address calculator: generates the ascending IPv4 sequence to scan from the configuration
/// (network, prefix, exclusion list, network/broadcast address policy, size cap).
/// </summary>
public sealed class RdpTargetCalculator
{
    public IReadOnlyList<ProbeTarget> Calculate(RdpDetectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!RdpDetectionOptionsValidator.TryParseNetwork(options, out var network))
        {
            throw new ArgumentException($"Network configuration cannot be parsed: '{options.Network}'", nameof(options));
        }

        var baseValue = ToUInt32(network.BaseAddress);
        var hostBits = 32 - network.PrefixLength;

        // Compute the first and last addresses.
        ulong first;
        ulong last;

        if (hostBits == 0)
        {
            // /32: a single address, included regardless of the network-address switch.
            first = last = baseValue;
        }
        else if (hostBits == 1)
        {
            // /31: modern point-to-point semantics, both addresses are usable hosts.
            first = baseValue;
            last = baseValue + 1;
        }
        else
        {
            var endExclusive = baseValue + (1UL << hostBits);
            first = options.IncludeNetworkAddress ? baseValue : baseValue + 1;
            last = options.IncludeBroadcastAddress
                ? endExclusive - 1
                : endExclusive - 2;
        }

        // Size cap protection (prevents huge networks such as /0, /8 from exhausting memory).
        var count = last >= first ? last - first + 1 : 0;
        if (count > (ulong)options.MaxScanAddresses)
        {
            throw new InvalidOperationException(
                $"Target address count {count} exceeds MaxScanAddresses({options.MaxScanAddresses}); shrink the network or raise the limit.");
        }

        // Exclusion set.
        var excluded = new HashSet<uint>();
        if (options.ExcludedAddresses is not null)
        {
            foreach (var item in options.ExcludedAddresses)
            {
                if (IPAddress.TryParse(item, out var address)
                    && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    excluded.Add(ToUInt32(address));
                }
            }
        }

        var results = new List<ProbeTarget>((int)count);
        for (var value = first; value <= last; value++)
        {
            var addressValue = (uint)value;
            if (excluded.Contains(addressValue))
            {
                continue;
            }

            results.Add(ProbeTarget.Create(FromUInt32(addressValue)));
        }

        return results;
    }

    internal static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    internal static IPAddress FromUInt32(uint value)
        => new(new[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value,
        });
}
