using Microsoft.IO;

namespace CosmosContentValidation;

/// <summary>Bounded pooled storage. Returned streams are owned by the caller and must be disposed.</summary>
/// <remarks>The pool is thread safe; individual streams and their cursors are not.</remarks>
public sealed class PooledJsonBufferPool
{
    private readonly RecyclableMemoryStreamManager manager;
    public int MaxBufferBytes { get; }

    public PooledJsonBufferPool(int maxBufferBytes = 8 * 1024 * 1024)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBufferBytes, 1024);
        MaxBufferBytes = maxBufferBytes;
        int blockSize = Math.Min(16 * 1024, maxBufferBytes);
        manager = new(new RecyclableMemoryStreamManager.Options
        {
            BlockSize = blockSize,
            LargeBufferMultiple = 256 * 1024,
            MaximumBufferSize = 8 * 1024 * 1024,
            MaximumSmallPoolFreeBytes = 16 * 1024 * 1024,
            MaximumLargePoolFreeBytes = 16 * 1024 * 1024,
            // Capacity is rounded to pool blocks; logical payload limits are enforced separately.
            MaximumStreamCapacity = ((long)maxBufferBytes + blockSize - 1) / blockSize * blockSize,
            ThrowExceptionOnToArray = true,
            ZeroOutBuffer = true
        });
    }

    /// <summary>Buffers currently leased, useful for ownership tests and diagnostics.</summary>
    public long InUseBytes => manager.SmallPoolInUseSize + manager.LargePoolInUseSize;

    public RecyclableMemoryStream Rent() => manager.GetStream();

    /// <summary>Copies from current position; leaves source open and restores position if seekable.</summary>
    public RecyclableMemoryStream Read(Stream source, int? limit = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        int bound = GetBound(limit);
        long? position = source.CanSeek ? source.Position : null;
        RecyclableMemoryStream result = Rent();
        try
        {
            try
            {
                while (true)
                {
                    if (result.Length == bound)
                    {
                        if (source.ReadByte() != -1) CheckLength(bound + 1L, bound);
                        break;
                    }
                    int capacity = (int)Math.Min(16 * 1024, bound - result.Length);
                    // Ask for one byte, then fill the actual remaining block. A larger hint
                    // can allocate a temporary buffer and copy on Advance in RMS 3.0.1.
                    Span<byte> available = result.GetSpan(1);
                    int count = source.Read(available[..Math.Min(capacity, available.Length)]);
                    if (count == 0) break;
                    CheckLength(result.Length + count, bound);
                    result.Advance(count);
                }
                result.Position = 0;
            }
            finally
            {
                if (position.HasValue) source.Position = position.Value;
            }
            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    /// <summary>Async transport I/O only; no crypto runs here. Source ownership is unchanged.</summary>
    public async Task<RecyclableMemoryStream> ReadAsync(Stream source, CancellationToken cancellationToken = default, int? limit = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        int bound = GetBound(limit);
        long? position = source.CanSeek ? source.Position : null;
        RecyclableMemoryStream result = Rent();
        try
        {
            try
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (result.Length == bound)
                    {
                        // One-byte EOF probe avoids growing the pooled payload merely to detect overflow.
                        byte[] probe = new byte[1];
                        if (await source.ReadAsync(probe, cancellationToken).ConfigureAwait(false) != 0)
                            CheckLength(bound + 1L, bound);
                        break;
                    }
                    int capacity = (int)Math.Min(16 * 1024, bound - result.Length);
                    Memory<byte> available = result.GetMemory(1);
                    int count = await source.ReadAsync(available[..Math.Min(capacity, available.Length)], cancellationToken).ConfigureAwait(false);
                    if (count == 0) break;
                    CheckLength(result.Length + count, bound);
                    result.Advance(count);
                }
                result.Position = 0;
            }
            finally
            {
                if (position.HasValue) source.Position = position.Value;
            }
            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    private int GetBound(int? limit)
    {
        int bound = limit ?? MaxBufferBytes;
        ArgumentOutOfRangeException.ThrowIfLessThan(bound, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(bound, MaxBufferBytes);
        return bound;
    }

    private static void CheckLength(long length, int bound)
    {
        if (length > bound)
            throw new ContentValidationException(ContentValidationFailure.PayloadTooLarge, "JSON exceeds the configured buffer limit.");
    }
}