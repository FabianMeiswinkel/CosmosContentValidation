using System.Net;
using Microsoft.Azure.Cosmos;
using Microsoft.IO;

namespace CosmosContentValidation;

/// <summary>Validates and replays successful stream query and change-feed pages.</summary>
internal sealed class ContentValidationFeedIterator : FeedIterator
{
    private readonly FeedIterator inner;
    private readonly ContentValidationProcessor processor;
    private int poisoned;
    private int disposed;
    private int innerDisposed;

    internal ContentValidationFeedIterator(FeedIterator inner, ContentValidationProcessor processor)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.processor = processor ?? throw new ArgumentNullException(nameof(processor));
    }

    public override bool HasMoreResults => Volatile.Read(ref disposed) == 0
        && Volatile.Read(ref poisoned) == 0 && inner.HasMoreResults;

    public override async Task<ResponseMessage> ReadNextAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();
        ResponseMessage? response = null;
        RecyclableMemoryStream? buffered = null;
        Stream? nativeContent = null;
        bool poisonOnFailure = false;
        try
        {
            response = await inner.ReadNextAsync(cancellationToken).ConfigureAwait(false);
            poisonOnFailure = true;
            cancellationToken.ThrowIfCancellationRequested();
            // Native error and 304 responses retain exact identity, content and ownership.
            if (!response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotModified)
                return response;
            nativeContent = response.Content;
            if (nativeContent is null)
                throw MissingBody();
            // QueryResponse can override Content and ignore the base setter. Clear ordinary
            // base-backed content and transfer the observed stream
            // separately so the facade deterministically disposes both response implementations.
            response.Content = null;
            buffered = await processor.Buffers.ReadAsync(nativeContent, cancellationToken).ConfigureAwait(false);
            if (buffered.Length == 0) throw MissingBody();
            cancellationToken.ThrowIfCancellationRequested();
            processor.ValidateFeedPage(buffered.GetReadOnlySequence());
            cancellationToken.ThrowIfCancellationRequested();
            buffered.Position = 0;
            ContentValidationResponseMessage facade = new(response, nativeContent, buffered);
            response = null;
            nativeContent = null;
            buffered = null;
            return facade;
        }
        catch
        {
            buffered?.Dispose();
            nativeContent?.Dispose();
            response?.Dispose();
            if (poisonOnFailure) Poison();
            throw;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref disposed, 1) == 0) DisposeInner();
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Volatile.Read(ref poisoned) != 0)
            throw new InvalidOperationException("The feed iterator is unusable after page validation or cancellation failed.");
    }

    private void Poison()
    {
        Interlocked.Exchange(ref poisoned, 1);
        DisposeInner();
    }

    private void DisposeInner()
    {
        if (Interlocked.Exchange(ref innerDisposed, 1) == 0) inner.Dispose();
    }

    private static ContentValidationException MissingBody() => new(ContentValidationFailure.InvalidDocument,
        "A successful feed response has no JSON envelope.");
}

/// <summary>Materializes native typed feed responses through the configured validating serializer.</summary>
internal sealed class ContentValidationFeedIterator<T> : FeedIterator<T>
{
    private readonly FeedIterator inner;
    private readonly ContentValidationProcessor processor;
    private readonly CosmosResponseFactory responseFactory;
    private int poisoned;
    private int disposed;
    private int innerDisposed;

    internal ContentValidationFeedIterator(FeedIterator inner, ContentValidationProcessor processor,
        CosmosResponseFactory responseFactory)
    {
        ContentValidationContainer.RejectSerializerBypassTarget<T>();
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.processor = processor ?? throw new ArgumentNullException(nameof(processor));
        this.responseFactory = responseFactory ?? throw new ArgumentNullException(nameof(responseFactory));
    }

    public override bool HasMoreResults => Volatile.Read(ref disposed) == 0
        && Volatile.Read(ref poisoned) == 0 && inner.HasMoreResults;

    public override async Task<FeedResponse<T>> ReadNextAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();
        ResponseMessage? response = null;
        RecyclableMemoryStream? buffered = null;
        MemoryStream? normalized = null;
        Stream? nativeContent = null;
        bool poisonOnFailure = false;
        try
        {
            response = await inner.ReadNextAsync(cancellationToken).ConfigureAwait(false);
            poisonOnFailure = true;
            cancellationToken.ThrowIfCancellationRequested();
            poisonOnFailure = response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotModified;
            if (response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NotModified)
            {
                nativeContent = response.Content;
                if (nativeContent is null)
                    throw new ContentValidationException(ContentValidationFailure.InvalidDocument,
                        "A successful typed feed response has no JSON envelope.");
                response.Content = null;
                buffered = await processor.Buffers.ReadAsync(nativeContent, cancellationToken).ConfigureAwait(false);
                if (buffered.Length == 0)
                    throw new ContentValidationException(ContentValidationFailure.InvalidDocument,
                        "A successful typed feed response has an empty JSON envelope.");
                cancellationToken.ThrowIfCancellationRequested();
                normalized = processor.NormalizeFeedPageForFactory(buffered.GetReadOnlySequence());
                cancellationToken.ThrowIfCancellationRequested();
                response = new ContentValidationResponseMessage(response, nativeContent, normalized);
                nativeContent = null;
                normalized = null;
                buffered.Dispose();
                buffered = null;
            }
            // Cosmos 3.63.2's native response factory takes ownership even when materialization
            // throws. Transfer before calling it so exceptional paths cannot double-dispose.
            ResponseMessage owned = response;
            response = null;
            FeedResponse<T> materialized = responseFactory.CreateItemFeedResponse<T>(owned);
            cancellationToken.ThrowIfCancellationRequested();
            return materialized;
        }
        catch
        {
            normalized?.Dispose();
            buffered?.Dispose();
            nativeContent?.Dispose();
            response?.Dispose();
            if (poisonOnFailure) Poison();
            throw;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref disposed, 1) == 0) DisposeInner();
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Volatile.Read(ref poisoned) != 0)
            throw new InvalidOperationException("The feed iterator is unusable after page materialization or cancellation failed.");
    }

    private void Poison()
    {
        Interlocked.Exchange(ref poisoned, 1);
        DisposeInner();
    }

    private void DisposeInner()
    {
        if (Interlocked.Exchange(ref innerDisposed, 1) == 0) inner.Dispose();
    }
}
