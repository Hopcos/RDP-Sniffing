using Microsoft.Extensions.Options;
using RdpSniffer.Core.Options;
using Xunit;

namespace RdpSniffer.Tests;

public class OptionsValidationTests
{
    private static RdpDetectionOptions Options(Action<RdpDetectionOptions>? configure = null)
    {
        var options = new RdpDetectionOptions();
        configure?.Invoke(options);
        return options;
    }

    private static ValidateOptionsResult Validate(RdpDetectionOptions options)
        => new RdpDetectionOptionsValidator().Validate(null, options);

    [Fact]
    public void DefaultOptions_ValidatePasses()
    {
        var result = Validate(Options());
        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? Array.Empty<string>()));
    }

    [Fact]
    public void VerifyCredentialsTrue_WithoutUserName_Fails()
    {
        var result = Validate(Options(o =>
        {
            o.VerifyCredentials = true;
            o.Credentials.Password = "secret";
        }));

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("UserName"));
    }

    [Fact]
    public void VerifyCredentialsTrue_WithoutPassword_Fails()
    {
        var result = Validate(Options(o =>
        {
            o.VerifyCredentials = true;
            o.Credentials.UserName = "admin";
        }));

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Password"));
    }

    [Fact]
    public void VerifyCredentialsTrue_WithCredentials_Passes()
    {
        var result = Validate(Options(o =>
        {
            o.VerifyCredentials = true;
            o.Credentials.UserName = "admin";
            o.Credentials.Password = "secret";
        }));

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void VerifyCredentialsFalse_NoCredentialsRequired()
    {
        var result = Validate(Options(o => o.VerifyCredentials = false));
        Assert.True(result.Succeeded);
    }

    [Fact]
    public void InvalidNetwork_Fails()
    {
        var result = Validate(Options(o => o.Network = "10.0.5.999/24"));
        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Network"));
    }

    [Fact]
    public void InvalidExcludedAddress_Fails()
    {
        var result = Validate(Options(o => o.ExcludedAddresses = new List<string> { "not-an-ip" }));
        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("ExcludedAddresses"));
    }

    [Fact]
    public void PortZero_Fails()
    {
        var result = Validate(Options(o => o.Port = 0));
        Assert.True(result.Failed);
    }

    [Fact]
    public void InvalidScanInterval_Fails()
    {
        var result = Validate(Options(o => o.ScanInterval = "abc"));
        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("ScanInterval"));
    }

    [Fact]
    public void PlainIpWithPrefixLength_Passes()
    {
        var result = Validate(Options(o =>
        {
            o.Network = "10.0.5.0";
            o.PrefixLength = 24;
        }));
        Assert.True(result.Succeeded);
    }

    [Fact]
    public void PrefixLengthOutOfRange_Fails()
    {
        var result = Validate(Options(o => o.PrefixLength = 33));
        Assert.True(result.Failed);
    }

    [Fact]
    public void MultipleErrors_AllCollected()
    {
        var result = Validate(Options(o =>
        {
            o.Network = "bad";
            o.Port = 0;
            o.VerifyCredentials = true; // missing user name and password
        }));

        Assert.True(result.Failed);
        Assert.NotEmpty(result.Failures);
        Assert.Contains(result.Failures, f => f.Contains("Network"));
        Assert.Contains(result.Failures, f => f.Contains("Port"));
        Assert.Contains(result.Failures, f => f.Contains("UserName"));
    }
}
