using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace RdpSniffer.Core.Options;

/// <summary>
/// Configuration validator: DataAnnotations + business rules (network must be parseable, excluded addresses
/// must be valid IPv4, VerifyCredentials=true requires user name and password, valid scan interval).
/// Used both at application startup (ValidateOnStart) and directly by unit tests.
/// </summary>
public sealed class RdpDetectionOptionsValidator : IValidateOptions<RdpDetectionOptions>
{
    public ValidateOptionsResult Validate(string? name, RdpDetectionOptions options)
    {
        var errors = new List<string>();

        // 1) DataAnnotations basic validation
        var validationContext = new ValidationContext(options);
        var validationResults = new List<ValidationResult>();
        if (!Validator.TryValidateObject(options, validationContext, validationResults, validateAllProperties: true))
        {
            foreach (var result in validationResults)
            {
                errors.Add(result.ErrorMessage ?? "Configuration validation failed");
            }
        }

        // 2) Network must be parseable
        if (!TryParseNetwork(options, out _))
        {
            errors.Add($"Network cannot be parsed as an IPv4 network: '{options.Network}' (use 10.0.5.0/24 or 10.0.5.0 + PrefixLength)");
        }

        // 3) Excluded addresses must be valid IPv4
        if (options.ExcludedAddresses is not null)
        {
            foreach (var item in options.ExcludedAddresses)
            {
                if (!TryParseIpv4(item, out _))
                {
                    errors.Add($"ExcludedAddresses contains an invalid IPv4 address: '{item}'");
                }
            }
        }

        // 4) Credential pairing constraint
        if (options.VerifyCredentials)
        {
            if (string.IsNullOrWhiteSpace(options.Credentials.UserName))
            {
                errors.Add("VerifyCredentials=true requires Credentials.UserName");
            }

            if (string.IsNullOrWhiteSpace(options.Credentials.Password))
            {
                errors.Add("VerifyCredentials=true requires Credentials.Password");
            }
        }

        // 5) Scan interval
        if (!TimeSpan.TryParse(options.ScanInterval, out var interval) || interval < TimeSpan.FromSeconds(5))
        {
            errors.Add($"ScanInterval must be a time span of at least 00:00:05, current value: '{options.ScanInterval}'");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }

    /// <summary>Parses the configuration into an <see cref="IPNetwork"/>: supports "10.0.5.0/24" or "10.0.5.0" + PrefixLength.</summary>
    public static bool TryParseNetwork(RdpDetectionOptions options, out IPNetwork network)
    {
        var text = options.Network?.Trim() ?? string.Empty;
        var slash = text.IndexOf('/');

        if (slash > 0)
        {
            // CIDR notation
            var ipPart = text[..slash];
            if (int.TryParse(text.AsSpan(slash + 1), out var prefix)
                && prefix is >= 0 and <= 32
                && IPAddress.TryParse(ipPart, out var baseAddress)
                && baseAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                network = new IPNetwork(baseAddress, prefix);
                return true;
            }
        }
        else if (IPAddress.TryParse(text, out var plainAddress)
                 && plainAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            // Plain IP notation; the prefix comes from PrefixLength (already bounded to 0..32 by DataAnnotations)
            network = new IPNetwork(plainAddress, options.PrefixLength);
            return true;
        }

        // Failure path: return the struct default (callers only use it when true is returned)
        network = default;
        return false;
    }

    private static bool TryParseIpv4(string? text, out IPAddress address)
    {
        address = IPAddress.Any;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        if (!IPAddress.TryParse(text, out var parsed) || parsed is null)
        {
            return false;
        }

        if (parsed.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        address = parsed;
        return true;
    }
}
