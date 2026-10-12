using System.Text;
using System.Text.Json;

namespace CosmosContentValidation.Sample.Providers;

/// <summary>Validates the entire input tree, before any ignored-property filtering.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// </remarks>
internal static class UnsafeJsonInputValidation
{
    private const int MaxCollectionDepth = 64;
    private const double MaxSafeInteger = 9007199254740991d;

    /// <summary>
    /// Checks decoded ordinal name uniqueness, Unicode, binary64 numbers, and depth.
    /// Every property is visited, including service metadata and other ignored fields.
    /// </summary>
    /// <remarks>
    /// GetString and JsonProperty.Name force System.Text.Json's lazy strict decoding
    /// of UTF-8 and escaped surrogates. Input already replaced with U+FFFD by a
    /// serializer cannot be distinguished from a genuine replacement character.
    /// </remarks>
    internal static void Validate(JsonElement value)
    {
        try
        {
            ValidateCore(value, 0);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException
            or DecoderFallbackException or FormatException)
        {
            // Lazy decoding diagnostics may include property names or string data.
            // Never attach those exceptions as InnerException, either.
            throw new JsonException("JSON does not conform to the supported canonicalization profile.");
        }
    }

    private static void ValidateCore(JsonElement value, int collectionDepth)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                CheckCollectionDepth(collectionDepth);
                HashSet<string> names = new(StringComparer.Ordinal);
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    string name = property.Name;
                    ValidateUnicode(name);
                    if (!names.Add(name))
                        throw new JsonException("Duplicate JSON property names are not supported.");
                    ValidateCore(property.Value, collectionDepth + 1);
                }
                break;

            case JsonValueKind.Array:
                CheckCollectionDepth(collectionDepth);
                foreach (JsonElement item in value.EnumerateArray())
                    ValidateCore(item, collectionDepth + 1);
                break;

            case JsonValueKind.String:
                ValidateUnicode(value.GetString()!);
                break;

            case JsonValueKind.Number:
                ValidateNumber(value);
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                break;

            default:
                throw new JsonException("Unsupported JSON value kind.");
        }
    }

    private static void CheckCollectionDepth(int parentDepth)
    {
        // Scalars consume no depth; the root collection consumes the first level.
        if (parentDepth >= MaxCollectionDepth)
            throw new JsonException("JSON collection depth exceeds the supported limit.");
    }

    private static void ValidateUnicode(string text)
    {
        for (int index = 0; index < text.Length; index++)
        {
            char current = text[index];
            if (!char.IsSurrogate(current)) continue;
            if (!char.IsHighSurrogate(current) || index + 1 == text.Length
                || !char.IsLowSurrogate(text[index + 1]))
                throw new JsonException("JSON contains invalid Unicode.");
            index++;
        }
    }

    private static void ValidateNumber(JsonElement value)
    {
        if (!value.TryGetDouble(out double number) || !double.IsFinite(number))
            throw new JsonException("JSON numbers must be finite binary64 values.");

        // Check the binary64 result, not the presence of a decimal point or exponent.
        // In particular, fractional lexemes that round to unsafe integers also fail.
        if (Math.Truncate(number) == number && Math.Abs(number) > MaxSafeInteger)
            throw new JsonException("Integral JSON numbers exceed the supported range.");

        if (number == 0)
        {
            // Allocate raw text only for this numeric lexeme, never for a JSON body.
            // Exponent digits do not make an all-zero mantissa nonzero (0e-999 is valid).
            foreach (char character in value.GetRawText())
            {
                if (character is 'e' or 'E') break;
                if (character is >= '1' and <= '9')
                    throw new JsonException("Nonzero JSON numbers must not underflow to zero.");
            }
        }
    }
}