using System.Buffers;
using Microsoft.IO;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class BufferPoolTests
{
    [Fact]
    public void DefaultLimitIsEightMiBAndRentTransfersOneLeaseToCaller()
    {
        PooledJsonBufferPool pool = new();
        Assert.Equal(8 * 1024 * 1024, pool.MaxBufferBytes);
        Assert.Equal(0L, pool.InUseBytes);
        RecyclableMemoryStream rented = pool.Rent();
        using (rented)
        {
            Assert.True(rented.CanRead);
            Assert.True(rented.CanSeek);
            Assert.True(rented.CanWrite);
            Assert.Equal(0L, rented.Position);
            Assert.Equal(0L, rented.Length);
            rented.Write("leased"u8);
            Assert.True(pool.InUseBytes > 0);
        }
        Assert.False(rented.CanRead);
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Theory]
    [InlineData(int.MinValue)]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1023)]
    public void ConstructorRejectsLimitsSmallerThanOneKiB(int limit)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new PooledJsonBufferPool(limit));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NullAndInvalidPerReadLimitsRejectBeforeReadingOrLeasing(bool asynchronous)
    {
        PooledJsonBufferPool pool = new(1024);
        await Assert.ThrowsAsync<ArgumentNullException>(() => Copy(pool, null!, asynchronous));
        using SourceStream source = new(Data(31), start: 7);
        foreach (int limit in new[] { int.MinValue, -1, 0, 1025, int.MaxValue })
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Copy(pool, source, asynchronous, limit));
            Assert.Equal(0, source.ReadCalls);
            Assert.Equal(0, source.PositionGets);
            Assert.Equal(0, source.PositionSets);
            Assert.Equal(7L, source.ObservedPosition);
            Assert.Equal(0, source.DisposeCalls);
            Assert.Equal(0L, pool.InUseBytes);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task UnknownLengthPartialReadsRespectSourceRegionAndPositionAndProduceSegmentedReplay(bool asynchronous, bool seekable)
    {
        PooledJsonBufferPool pool = new();
        byte[] payload = Data(40_123);
        const int origin = 3;
        const int prefix = 11;
        byte[] backing = [.. Data(origin + prefix, 99), .. payload, 0xFE, 0xFF];
        byte[] snapshot = (byte[])backing.Clone();
        using SourceStream source = new(backing, seekable, start: prefix, maxRead: 113, offset: origin, count: prefix + payload.Length);
        using (RecyclableMemoryStream result = await Copy(pool, source, asynchronous))
        {
            Assert.Equal(0L, result.Position);
            Assert.Equal(payload.Length, result.Length);
            Assert.True(result.CanSeek);
            Assert.True(source.ReadCalls > 2);
            Assert.Equal(0, source.LengthGets); // Even a seekable source need not expose Length.
            Assert.Equal(seekable ? prefix : prefix + payload.Length, source.ObservedPosition);
            Assert.Equal(seekable ? 1 : 0, source.PositionGets);
            Assert.Equal(seekable ? 1 : 0, source.PositionSets);
            Assert.Equal(0, source.DisposeCalls);
            Assert.True(source.CanRead);
            Assert.Equal(snapshot, backing);
            Assert.True(pool.InUseBytes > 0);
            if (asynchronous)
            {
                Assert.Equal(source.ReadCalls, source.AsyncReadCalls);
                Assert.Equal(0, source.SyncReadCalls);
            }
            else
            {
                Assert.Equal(source.ReadCalls, source.SyncReadCalls);
                Assert.Equal(0, source.AsyncReadCalls);
            }

            result.Position = 31;
            ReadOnlySequence<byte> sequence = result.GetReadOnlySequence();
            Assert.False(sequence.IsSingleSegment);
            Assert.Equal(payload.Length, sequence.Length);
            Assert.Equal(payload, sequence.ToArray());
            Assert.Equal(31L, result.Position); // The sequence represents the full body, not its unread tail.
            Array.Fill(backing, (byte)0xCC);
            Assert.Equal(payload, result.GetReadOnlySequence().ToArray());

            for (int replay = 0; replay < 2; replay++)
            {
                Assert.Equal(0L, result.Seek(0, SeekOrigin.Begin));
                byte[] actual = new byte[payload.Length];
                result.ReadExactly(actual);
                Assert.Equal(payload, actual);
                Assert.Equal(-1, result.ReadByte());
            }
        }
        Assert.Equal(0L, pool.InUseBytes);
        Assert.Equal(0, source.DisposeCalls);
        Assert.True(source.CanRead);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(false, 17)]
    [InlineData(true, 17)]
    public async Task EmptySourceAndSourceAlreadyAtEndReturnEmptyRewoundBuffer(bool asynchronous, int length)
    {
        PooledJsonBufferPool pool = new(1024);
        using SourceStream source = new(Data(length), start: length);
        using (RecyclableMemoryStream result = await Copy(pool, source, asynchronous))
        {
            Assert.Equal(0L, result.Length);
            Assert.Equal(0L, result.Position);
            Assert.True(result.GetReadOnlySequence().IsEmpty);
            Assert.Equal(-1, result.ReadByte());
            Assert.Equal(length, source.ObservedPosition);
            Assert.Equal(0, source.DisposeCalls);
        }
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Theory]
    [InlineData(false, 1024)]
    [InlineData(true, 1024)]
    [InlineData(false, 1025)]
    [InlineData(true, 1025)]
    [InlineData(false, 16_384)]
    [InlineData(true, 16_384)]
    [InlineData(false, 16_385)]
    [InlineData(true, 16_385)]
    [InlineData(false, 8 * 1024 * 1024)]
    [InlineData(true, 8 * 1024 * 1024)]
    public async Task ExactPoolBoundSucceedsButOneExtraByteFailsWithoutLeaking(bool asynchronous, int bound)
    {
        PooledJsonBufferPool pool = new(bound);
        Assert.Equal(bound, pool.MaxBufferBytes);
        foreach (bool seekable in new[] { false, true })
        {
            byte[] payload = Data(bound);
            using SourceStream exact = new([0xEE, .. payload], seekable, start: 1, maxRead: 4093);
            using (RecyclableMemoryStream result = await Copy(pool, exact, asynchronous))
            {
                Assert.Equal(bound, result.Length);
                Assert.Equal(0L, result.Position);
                Assert.Equal(payload, result.GetReadOnlySequence().ToArray());
                Assert.Equal(seekable ? 1L : bound + 1L, exact.ObservedPosition);
                Assert.True(pool.InUseBytes > 0);
            }
            Assert.Equal(0, exact.DisposeCalls);
            Assert.Equal(0L, pool.InUseBytes);

            using SourceStream overflow = new([0xEE, .. payload, 0xFF], seekable, start: 1, maxRead: 4093);
            ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(async () =>
            {
                using RecyclableMemoryStream unexpected = await Copy(pool, overflow, asynchronous);
            });
            Assert.Equal(ContentValidationFailure.PayloadTooLarge, failure.Failure);
            Assert.Equal(seekable ? 1L : bound + 2L, overflow.ObservedPosition);
            Assert.Equal(0, overflow.DisposeCalls);
            Assert.True(overflow.CanRead);
            Assert.Equal(0L, pool.InUseBytes);
        }
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    [InlineData(false, 17)]
    [InlineData(true, 17)]
    [InlineData(false, 1024)]
    [InlineData(true, 1024)]
    [InlineData(false, 16_385)]
    [InlineData(true, 16_385)]
    public async Task PerReadLimitIsLogicalNotRoundedCapacityAndMayBeSmallerThanPoolMinimum(bool asynchronous, int limit)
    {
        PooledJsonBufferPool pool = new(64 * 1024);
        byte[] bytes = Data(limit);
        using SourceStream exact = new(bytes, maxRead: 71);
        using (RecyclableMemoryStream result = await Copy(pool, exact, asynchronous, limit))
            Assert.Equal(bytes, result.GetReadOnlySequence().ToArray());
        using SourceStream overflow = new([.. bytes, 0xFF], maxRead: 71);
        ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(async () =>
        {
            using RecyclableMemoryStream unexpected = await Copy(pool, overflow, asynchronous, limit);
        });
        Assert.Equal(ContentValidationFailure.PayloadTooLarge, failure.Failure);
        Assert.Equal(0L, exact.ObservedPosition);
        Assert.Equal(0L, overflow.ObservedPosition);
        Assert.Equal(0, exact.DisposeCalls);
        Assert.Equal(0, overflow.DisposeCalls);
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CopyExceptionRestoresSeekablePositionAndReleasesLeaseWithoutOwningSource(bool asynchronous, bool seekable)
    {
        PooledJsonBufferPool pool = new();
        IOException sentinel = new("copy failed");
        using SourceStream source = new(Data(40_000), seekable, start: 7, maxRead: 4096)
        {
            FailOnRead = 2,
            ReadFailure = sentinel
        };
        IOException actual = await Assert.ThrowsAsync<IOException>(() => Copy(pool, source, asynchronous));
        Assert.Same(sentinel, actual);
        Assert.Equal(2, source.ReadCalls);
        Assert.Equal(seekable ? 7L : 4103L, source.ObservedPosition);
        Assert.Equal(0, source.DisposeCalls);
        Assert.True(source.CanRead);
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EofProbeExceptionAtExactBoundRestoresPositionAndReturnsLease(bool asynchronous)
    {
        PooledJsonBufferPool pool = new(1024);
        IOException sentinel = new("EOF probe failed");
        using SourceStream source = new(Data(1031), start: 7) { FailOnRead = 2, ReadFailure = sentinel };

        Assert.Same(sentinel, await Assert.ThrowsAsync<IOException>(() => Copy(pool, source, asynchronous)));

        Assert.Equal(2, source.ReadCalls);
        Assert.Equal(7L, source.ObservedPosition);
        Assert.Equal(0, source.DisposeCalls);
        Assert.True(source.CanRead);
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PositionRestorationFailureAlsoReturnsTheCompletedCopyToPool(bool asynchronous)
    {
        PooledJsonBufferPool pool = new();
        IOException sentinel = new("restore failed");
        using SourceStream source = new(Data(40_000), start: 7, maxRead: 4096) { RestoreFailure = sentinel };
        IOException actual = await Assert.ThrowsAsync<IOException>(() => Copy(pool, source, asynchronous));
        Assert.Same(sentinel, actual);
        Assert.Equal(1, source.PositionSets);
        Assert.Equal(0, source.DisposeCalls);
        Assert.True(source.CanRead);
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CancellationBeforeOrDuringCopyRestoresPositionAndReleasesLease(bool seekable, bool beforeCopy)
    {
        PooledJsonBufferPool pool = new();
        using CancellationTokenSource cancellation = new();
        using SourceStream source = new(Data(40_000), seekable, start: 7, maxRead: 257)
        {
            AfterRead = calls => { if (calls == 2) cancellation.Cancel(); }
        };
        if (beforeCopy) cancellation.Cancel();
        OperationCanceledException failure = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => pool.ReadAsync(source, cancellation.Token));
        Assert.Equal(cancellation.Token, failure.CancellationToken);
        Assert.Equal(beforeCopy ? 0 : 2, source.ReadCalls);
        Assert.Equal(seekable || beforeCopy ? 7L : 521L, source.ObservedPosition);
        if (!beforeCopy) Assert.Equal(cancellation.Token, source.LastToken);
        Assert.Equal(0, source.SyncReadCalls);
        Assert.Equal(0, source.DisposeCalls);
        Assert.True(source.CanRead);
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Fact]
    public async Task CancellationAtExactBoundIsObservedBeforeEofProbe()
    {
        PooledJsonBufferPool pool = new(1024);
        using CancellationTokenSource cancellation = new();
        using SourceStream source = new(Data(1024)) { AfterRead = _ => cancellation.Cancel() };
        OperationCanceledException failure = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => pool.ReadAsync(source, cancellation.Token));
        Assert.Equal(cancellation.Token, failure.CancellationToken);
        Assert.Equal(1, source.ReadCalls);
        Assert.Equal(0L, source.ObservedPosition);
        Assert.Equal(0, source.DisposeCalls);
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PooledSourceRemainsCallerOwnedAndItsCursorIsIndependentOfCopy(bool asynchronous)
    {
        PooledJsonBufferPool pool = new();
        byte[] bytes = Data(40_000);
        using (RecyclableMemoryStream source = pool.Rent())
        {
            source.Write(bytes);
            source.Position = 19;
            long sourceLease = pool.InUseBytes;
            using (RecyclableMemoryStream copy = await Copy(pool, source, asynchronous))
            {
                Assert.NotSame(source, copy);
                Assert.Equal(19L, source.Position);
                Assert.Equal(0L, copy.Position);
                Assert.Equal(bytes[19..], copy.GetReadOnlySequence().ToArray());
                Assert.True(pool.InUseBytes > sourceLease);
                source.Position = 0;
                source.WriteByte(0xFF);
                Assert.Equal(bytes[19..], copy.GetReadOnlySequence().ToArray());
                copy.Position = 13;
                Assert.Equal(1L, source.Position);
            }
            Assert.Equal(sourceLease, pool.InUseBytes);
            Assert.True(source.CanRead);
        }
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Fact]
    public void ToArrayIsForbiddenButReadOnlySequenceExposesOnlyLogicalBytesWithoutMovingCursor()
    {
        PooledJsonBufferPool pool = new();
        using (RecyclableMemoryStream stream = pool.Rent())
        {
            stream.Write(Data(40_000));
            stream.SetLength(17);
            stream.Position = 5;
            Assert.Throws<NotSupportedException>(() => stream.ToArray());
            Assert.Equal(5L, stream.Position);
            ReadOnlySequence<byte> sequence = stream.GetReadOnlySequence();
            Assert.Equal(17L, sequence.Length);
            Assert.Equal(Data(17), sequence.ToArray());
            Assert.Equal(5L, stream.Position);
        }
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Fact]
    public void PartiallyConsumedLeaseSurvivesOtherRentalsAndIsReplayableUntilDisposed()
    {
        PooledJsonBufferPool pool = new();
        byte[] payload = Data(40_123);
        using SourceStream source = new(payload);
        using (RecyclableMemoryStream held = pool.Read(source))
        {
            long heldLease = pool.InUseBytes;
            byte[] prefix = new byte[23];
            held.ReadExactly(prefix);
            Assert.Equal(payload[..23], prefix);
            for (int index = 0; index < 24; index++)
            {
                using (RecyclableMemoryStream other = pool.Rent())
                {
                    Assert.NotSame(held, other);
                    other.Write(Data(50_000, index + 1));
                    Assert.Equal(23L, held.Position);
                    Assert.Equal(payload, held.GetReadOnlySequence().ToArray());
                }
                Assert.Equal(heldLease, pool.InUseBytes);
            }
            byte[] tail = new byte[payload.Length - 23];
            held.ReadExactly(tail);
            Assert.Equal(payload[23..], tail);
            held.Position = 0;
            Assert.Equal(payload, held.GetReadOnlySequence().ToArray());
            Assert.Equal(0L, source.ObservedPosition);
        }
        Assert.Equal(0L, pool.InUseBytes);
        Assert.Equal(0, source.DisposeCalls);
    }

    [Fact]
    public async Task ConcurrentCopiesUseDistinctLeasesAndCursorsWithIndependentCallerOwnedSources()
    {
        PooledJsonBufferPool pool = new();
        const int workers = 16;
        int ready = 0;
        TaskCompletionSource allReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await Task.WhenAll(Enumerable.Range(0, workers).Select(index => Task.Run(async () =>
        {
            byte[] payload = Data(20_000 + index, index);
            using SourceStream source = new([0xFF, .. payload], start: 1, maxRead: 257);
            using (RecyclableMemoryStream result = await pool.ReadAsync(source))
            {
                result.Position = index + 1;
                if (Interlocked.Increment(ref ready) == workers) allReady.TrySetResult();
                await allReady.Task.WaitAsync(TimeSpan.FromSeconds(30));
                Assert.Equal(index + 1L, result.Position);
                Assert.Equal(payload, result.GetReadOnlySequence().ToArray());
                Assert.Equal((int)payload[index + 1], result.ReadByte());
                Assert.Equal(1L, source.ObservedPosition);
                Assert.Equal(0, source.DisposeCalls);
            }
            Assert.True(source.CanRead);
        })));
        Assert.Equal(0L, pool.InUseBytes);
    }

    private static Task<RecyclableMemoryStream> Copy(PooledJsonBufferPool pool, Stream source, bool asynchronous, int? limit = null) =>
        asynchronous ? pool.ReadAsync(source, limit: limit) : Task.FromResult(pool.Read(source, limit));

    private static byte[] Data(int length, int seed = 0)
    {
        byte[] result = new byte[length];
        for (int index = 0; index < result.Length; index++) result[index] = (byte)((index * 31 + seed) % 251);
        return result;
    }

    // Length deliberately throws for both modes. The region's origin and its logical Position
    // are distinct, just as with a MemoryStream over a subrange of a caller-owned byte array.
    private sealed class SourceStream : Stream
    {
        private readonly MemoryStream inner;
        private readonly bool seekable;
        private readonly int maxRead;
        public int ReadCalls { get; private set; }
        public int SyncReadCalls { get; private set; }
        public int AsyncReadCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public int LengthGets { get; private set; }
        public int PositionGets { get; private set; }
        public int PositionSets { get; private set; }
        public long ObservedPosition => inner.Position;
        public CancellationToken LastToken { get; private set; }
        public int FailOnRead { get; init; } = -1;
        public IOException? ReadFailure { get; init; }
        public IOException? RestoreFailure { get; init; }
        public Action<int>? AfterRead { get; init; }

        public SourceStream(byte[] bytes, bool seekable = true, int start = 0, int maxRead = int.MaxValue, int offset = 0, int? count = null)
        {
            inner = new(bytes, offset, count ?? bytes.Length - offset, writable: false, publiclyVisible: true) { Position = start };
            this.seekable = seekable;
            this.maxRead = maxRead;
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => seekable && inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length { get { LengthGets++; throw new NotSupportedException("Length is unknown."); } }
        public override long Position
        {
            get
            {
                PositionGets++;
                if (!seekable) throw new NotSupportedException();
                return inner.Position;
            }
            set
            {
                PositionSets++;
                if (!seekable) throw new NotSupportedException();
                if (RestoreFailure is not null) throw RestoreFailure;
                inner.Position = value;
            }
        }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            SyncReadCalls++;
            return ReadCore(buffer);
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            AsyncReadCalls++;
            LastToken = cancellationToken;
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadCore(buffer.Span));
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        private int ReadCore(Span<byte> buffer)
        {
            ReadCalls++;
            if (ReadCalls == FailOnRead) throw ReadFailure ?? new IOException("copy failed");
            int read = inner.Read(buffer[..Math.Min(buffer.Length, maxRead)]);
            AfterRead?.Invoke(ReadCalls);
            return read;
        }
        public override long Seek(long offset, SeekOrigin origin) => seekable ? inner.Seek(offset, origin) : throw new NotSupportedException();
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) { DisposeCalls++; inner.Dispose(); }
            base.Dispose(disposing);
        }
    }
}