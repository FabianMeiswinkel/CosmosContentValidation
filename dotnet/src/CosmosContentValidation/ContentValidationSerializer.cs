using System.Text.Json;
using Microsoft.Azure.Cosmos;
using Microsoft.IO;

namespace CosmosContentValidation;

/// <summary>Signs complete documents and verifies raw JSON before application deserialization.</summary>
/// <remarks>
/// Use together with the guarded client. Raw SDK stream APIs bypass this hook. ToStream output
/// belongs to the SDK. FromStream owns its input (including on failure). An injected ordinary
/// serializer is caller-owned, must be thread safe, and must not perform I/O or content protection.
/// Query parameters are not documents: the guarded query builder uses the ordinary delegate.
/// </remarks>
public sealed class ContentValidationSerializer : CosmosSerializer
{
    private readonly ContentValidationProcessor processor;
    private readonly CosmosSerializer inner;

    public ContentValidationSerializer(ContentValidationProcessor processor, CosmosSerializer? inner = null)
    {
        this.processor = processor ?? throw new ArgumentNullException(nameof(processor));
        this.inner = inner ?? new PooledSystemTextJsonSerializer(processor.Buffers);
        if (inner is ContentValidationSerializer)
            throw new ArgumentException("Do not stack content-validation serializers.", nameof(inner));
    }

    public override Stream ToStream<T>(T input)
    {
        RejectStreamType<T>();
        if (input is Stream) throw new NotSupportedException("Use the guarded stream API for raw JSON.");
        RecyclableMemoryStream? signed = null;
        try
        {
            using (Stream serialized = inner.ToStream(input))
            {
                // The default delegate already writes directly into our pool, avoiding a second body copy.
                if (serialized is RecyclableMemoryStream pooled && pooled.Position == 0)
                    signed = processor.Sign(pooled.GetReadOnlySequence());
                else
                {
                    using RecyclableMemoryStream buffered = processor.Buffers.Read(serialized, processor.MaxDocumentBytes);
                    signed = processor.Sign(buffered.GetReadOnlySequence());
                }
            }
            // Transfer only after delegate disposal succeeds; a throwing Dispose must not orphan output.
            return signed;
        }
        catch
        {
            signed?.Dispose();
            throw;
        }
    }

    public override T FromStream<T>(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using (stream)
        {
            RejectStreamType<T>();
            if (stream is RecyclableMemoryStream pooled && pooled.Position == 0)
                return Materialize<T>(pooled);
            using RecyclableMemoryStream buffered = processor.Buffers.Read(stream);
            return Materialize<T>(buffered);
        }
    }

    /// <summary>Serializes a query parameter through the ordinary delegate without signing it.</summary>
    internal Stream SerializeUnprotectedParameter(object? value) => inner.ToStream(value);

    private T Materialize<T>(RecyclableMemoryStream source)
    {
        using RecyclableMemoryStream verified = processor.ValidateAndStrip(source.GetReadOnlySequence(), allowArray: typeof(T).IsArray);
        // A delegate owns FromStream's argument; give it a non-owning view so the pooled owner
        // is returned exactly once, even when the delegate throws or forgets to dispose its view.
        return inner.FromStream<T>(new BorrowedReadStream(verified));
    }

    private static void RejectStreamType<T>()
    {
        if (typeof(Stream).IsAssignableFrom(typeof(T)))
            throw new NotSupportedException("Stream targets bypass typed deserialization. Use the guarded stream API.");
    }

    private sealed class BorrowedReadStream(Stream inner) : Stream
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

/// <summary>Ordinary model mapping. Protection is provided by ContentValidationSerializer, not here.</summary>
internal sealed class PooledSystemTextJsonSerializer(PooledJsonBufferPool buffers) : CosmosSerializer
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 64 };

    public override T FromStream<T>(Stream stream)
    {
        using (stream) return JsonSerializer.Deserialize<T>(stream, Options)!;
    }

    public override Stream ToStream<T>(T input)
    {
        RecyclableMemoryStream output = buffers.Rent();
        try
        {
            using Internal.BoundedBufferWriter destination = new(output, buffers.MaxBufferBytes);
            using (Utf8JsonWriter writer = new(destination)) JsonSerializer.Serialize(writer, input, Options);
            output.Position = 0;
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }
}