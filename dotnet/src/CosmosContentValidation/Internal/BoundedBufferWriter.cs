using System.Buffers;

namespace CosmosContentValidation.Internal;

/// <summary>Checks logical length without confusing a writer's reservation hint with bytes written.</summary>
internal sealed class BoundedBufferWriter(IBufferWriter<byte> destination, int limit) : IBufferWriter<byte>, IDisposable
{
    private int written;
    private byte[]? scratch;
    private bool usingScratch;
    private bool reservedDestination;

    public void Advance(int count)
    {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        if (count > limit - written)
            throw TooLarge();
        if (usingScratch)
        {
            ReadOnlySpan<byte> remaining = scratch.AsSpan(0, count);
            while (!remaining.IsEmpty)
            {
                Span<byte> target = destination.GetSpan(1);
                int copied = Math.Min(remaining.Length, target.Length);
                remaining[..copied].CopyTo(target);
                destination.Advance(copied);
                remaining = remaining[copied..];
            }
            usingScratch = false;
        }
        else
        {
            destination.Advance(count);
            reservedDestination = false;
        }
        written += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);
        sizeHint = Math.Max(sizeHint, 1);
        // Utf8JsonWriter reserves worst-case escaping space (up to six bytes per input byte)
        // plus growth slack, even when the actual representation fits. Never clamp its returned
        // span below sizeHint: that violates IBufferWriter. Use bounded, temporary pooled scratch
        // only at this boundary; Advance enforces the actual JSON limit before copying any bytes.
        if ((long)sizeHint > (long)limit * 6 + 4096) throw TooLarge();
        usingScratch = sizeHint > limit - written;
        if (!usingScratch)
        {
            Memory<byte> memory = destination.GetMemory(sizeHint);
            reservedDestination = true;
            return memory;
        }
        if (reservedDestination)
        {
            destination.Advance(0);
            reservedDestination = false;
        }
        if (scratch is null || scratch.Length < sizeHint)
        {
            if (scratch is not null) ArrayPool<byte>.Shared.Return(scratch, clearArray: true);
            scratch = null;
            scratch = ArrayPool<byte>.Shared.Rent(sizeHint);
        }
        return scratch;
    }

    public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

    public void Dispose()
    {
        // RMS 3.0.1 does not return an outstanding temporary IBufferWriter buffer on
        // Dispose. Complete its reservation even if JSON serialization failed mid-write.
        if (reservedDestination) destination.Advance(0);
        reservedDestination = false;
        if (scratch is not null) ArrayPool<byte>.Shared.Return(scratch, clearArray: true);
        scratch = null;
    }

    private static ContentValidationException TooLarge() =>
        new(ContentValidationFailure.PayloadTooLarge, "JSON exceeds the configured buffer limit.");
}