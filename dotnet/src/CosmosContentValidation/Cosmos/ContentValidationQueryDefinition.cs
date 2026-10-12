using System.Text;
using System.Text.Json;
using Microsoft.Azure.Cosmos;

namespace CosmosContentValidation;

/// <summary>A rebuildable query definition whose ordinary parameters bypass document signing.</summary>
/// <remarks>
/// Parameter names are replaced using exact ordinal comparison and move to the end of the ordered
/// parameter list. Ordinary values are retained by reference until <c>Build</c>; each build then
/// serializes a fresh immutable native query snapshot. Raw JSON and stream parameters are copied
/// immediately and are limited to one MiB. This type must not be cast to <see cref="QueryDefinition"/>
/// to add parameters; such bypasses are detected and rejected by <c>Build</c>.
/// </remarks>
public sealed class ContentValidationQueryDefinition : QueryDefinition
{
    private const int MaxParameterBytes = 1024 * 1024;
    private readonly List<Parameter> parameters = [];

    public ContentValidationQueryDefinition(string queryText) : base(queryText)
    {
    }

    /// <summary>Adds or replaces an ordinary parameter, serialized only when the query is built.</summary>
    public new ContentValidationQueryDefinition WithParameter(string name, object? value)
    {
        ValidateName(name);
        Replace(new Parameter(name, value, null));
        return this;
    }

    /// <summary>Adds or replaces a pre-serialized strict JSON parameter, copied immediately.</summary>
    public ContentValidationQueryDefinition WithRawJsonParameter(string name, ReadOnlyMemory<byte> value)
    {
        ValidateName(name);
        if (value.Length > MaxParameterBytes)
            throw new ContentValidationException(ContentValidationFailure.PayloadTooLarge,
                "A raw query parameter exceeds the one MiB size limit.");
        byte[] snapshot = value.ToArray();
        ValidateStrictJson(snapshot);
        Replace(new Parameter(name, null, snapshot));
        return this;
    }

    /// <summary>Consumes from the current position, disposes the supplied stream, and stores a copy.</summary>
    public new ContentValidationQueryDefinition WithParameterStream(string name, Stream value)
    {
        ValidateName(name);
        ArgumentNullException.ThrowIfNull(value);
        byte[] snapshot;
        using (value)
        {
            using MemoryStream destination = new();
            byte[] buffer = new byte[16 * 1024];
            while (destination.Length < MaxParameterBytes)
            {
                int count = value.Read(buffer, 0, (int)Math.Min(buffer.Length, MaxParameterBytes - destination.Length));
                if (count == 0) break;
                destination.Write(buffer, 0, count);
            }
            if (destination.Length == MaxParameterBytes && value.ReadByte() != -1)
                throw new ContentValidationException(ContentValidationFailure.PayloadTooLarge,
                    "A raw query parameter exceeds the one MiB size limit.");
            snapshot = destination.ToArray();
        }
        ValidateStrictJson(snapshot);
        Replace(new Parameter(name, null, snapshot));
        return this;
    }

    /// <summary>Builds a fresh native SDK query definition with immutable serialized parameters.</summary>
    internal QueryDefinition Build(ContentValidationSerializer serializer)
    {
        ArgumentNullException.ThrowIfNull(serializer);
        if (base.GetQueryParameters().Count != 0)
            throw new ContentValidationException(ContentValidationFailure.UnsupportedOperation,
                "Parameters added through the base QueryDefinition API cannot be safely rebuilt.");

        QueryDefinition result = new(QueryText);
        foreach (Parameter parameter in parameters)
        {
            using Stream serialized = parameter.RawJson is null
                ? serializer.SerializeUnprotectedParameter(parameter.Value)
                : new MemoryStream(parameter.RawJson, writable: false);
            // Cosmos 3.63.2 synchronously consumes and disposes its argument. Give it a view so
            // the real serializer-owned stream remains under this method's exact-once ownership.
            using NonOwningReadStream view = new(serialized);
            result.WithParameterStream(parameter.Name, view);
        }
        return result;
    }

    private void Replace(Parameter parameter)
    {
        parameters.RemoveAll(existing => string.Equals(existing.Name, parameter.Name, StringComparison.Ordinal));
        parameters.Add(parameter);
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name)) throw new ArgumentNullException(nameof(name));
    }

    private static void ValidateStrictJson(ReadOnlyMemory<byte> json)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
            ValidateValue(document.RootElement);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException
            or FormatException or DecoderFallbackException)
        {
            throw new ContentValidationException(ContentValidationFailure.InvalidDocument,
                "A raw query parameter must contain exactly one strict UTF-8 JSON value.",
                new JsonException("Malformed JSON, duplicate names, invalid Unicode or excessive depth."));
        }
    }

    private static void ValidateValue(JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                HashSet<string> names = new(StringComparer.Ordinal);
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    if (!IsValidUnicode(property.Name) || !names.Add(property.Name))
                        throw new JsonException("Object names must be unique valid Unicode.");
                    ValidateValue(property.Value);
                }
                break;
            case JsonValueKind.Array:
                foreach (JsonElement item in value.EnumerateArray()) ValidateValue(item);
                break;
            case JsonValueKind.String:
                if (!IsValidUnicode(value.GetString()!)) throw new JsonException("Strings must be valid Unicode.");
                break;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                break;
            default:
                throw new JsonException("Unsupported JSON token.");
        }
    }

    private static bool IsValidUnicode(string text)
    {
        for (int index = 0; index < text.Length; index++)
        {
            if (!char.IsSurrogate(text[index])) continue;
            if (!char.IsHighSurrogate(text[index]) || ++index == text.Length || !char.IsLowSurrogate(text[index]))
                return false;
        }
        return true;
    }

    private sealed record Parameter(string Name, object? Value, byte[]? RawJson);

    private sealed class NonOwningReadStream(Stream inner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => inner.Read(buffer);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
