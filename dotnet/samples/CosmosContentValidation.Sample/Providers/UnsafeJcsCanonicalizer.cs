using System.Buffers;
using System.Text;
using System.Text.Json;

namespace CosmosContentValidation.Sample.Providers;

/// <summary>RFC 8785 canonicalization with the versioned, strict binary64 input profile.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// Nonintegral numbers are rounded to IEEE 754 binary64 before canonicalization.
/// Integral binary64 results must be within +/-9007199254740991; overflow and
/// nonzero underflow are rejected. Transport exact decimals and large integers as strings.
/// This adapter is thread safe and neither retains nor disposes its borrowed arguments.
/// </remarks>
public sealed class UnsafeJcsCanonicalizer : IJsonCanonicalizer
{
    public const string SupportedProfileId = "rfc8785-binary64-v1";

    public string ProfileId => SupportedProfileId;

    public void ValidateInput(JsonElement value) => UnsafeJsonInputValidation.Validate(value);

    public void Canonicalize(JsonElement value, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ValidateInput(value);

        byte[] canonical;
        try
        {
            // The provider's returned canonical bytes are the sole whole-body
            // allocation here. Do not flatten the input or copy this array again.
            canonical = Jcs.Net.JsonCanonicalizer.CanonicalizeToUtf8(value);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException
            or DecoderFallbackException or FormatException)
        {
            // Provider diagnostics can contain input. Do not retain an inner exception.
            throw new JsonException("JSON cannot be canonicalized under the supported profile.");
        }

        // Destination failures are not JSON failures and must propagate unchanged.
        destination.Write(canonical);
    }
}