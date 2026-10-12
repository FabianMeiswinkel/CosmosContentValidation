using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Scripts;
using Microsoft.IO;

namespace CosmosContentValidation;

/// <summary>Protects typed and stream point creates/reads; permits point deletes for cleanup.</summary>
/// <remarks>
/// Every create requires an explicit partition key. Provisioning must verify that actual container
/// partition-key paths match ContentValidationProcessor.PartitionKeyPaths. This wrapper does not
/// infer paths from a document or perform provisioning. All other content operations are blocked.
/// Typed operations use the SDK serializer exactly once. Stream operations retain signed JSON.
/// Caller input stays open; a seekable input's original position is restored. A successful returned
/// response owns its pooled body until disposed. Service errors and delete responses are untouched.
/// No-content writes are status-only, not proof of returned-content validation. A validation error
/// after a successful create does not roll back the committed write.
/// Nonempty successful stream responses are validated even when write content is disabled.
/// Typed item targets exclude streams and SDK resource DTOs that bypass the custom serializer.
/// Typed content responses must materialize a nondefault value: the SDK returns default(T) without
/// invoking the serializer for an absent body, so default-valued structs are deliberately rejected.
/// </remarks>
public sealed class ContentValidationContainer : Container
{
    private readonly ContentValidationDatabase database;
    private readonly Container inner;
    private readonly ContentValidationProcessor processor;
    private readonly bool contentResponseOnWrite;

    internal ContentValidationContainer(ContentValidationDatabase database, Container inner, ContentValidationProcessor processor, bool contentResponseOnWrite = true)
    {
        this.database = database ?? throw new ArgumentNullException(nameof(database));
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.processor = processor ?? throw new ArgumentNullException(nameof(processor));
        this.contentResponseOnWrite = contentResponseOnWrite;
    }

    public override string Id => inner.Id;
    public override Database Database => database;

    public override Task<ItemResponse<T>> CreateItemAsync<T>(T item, PartitionKey? partitionKey = null, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireSigner();
        RejectSerializerBypassTarget<T>();
        ArgumentNullException.ThrowIfNull(item);
        if (item is Stream) throw Unsupported();
        if (!partitionKey.HasValue) throw new ArgumentException("An explicit partition key is required.", nameof(partitionKey));
        ItemRequestOptions? snapshot = SnapshotOptions(requestOptions);
        cancellationToken.ThrowIfCancellationRequested();
        return RequireTypedContentAsync(inner.CreateItemAsync(item, partitionKey, snapshot, cancellationToken),
            snapshot?.EnableContentResponseOnWrite ?? contentResponseOnWrite);
    }

    public override Task<ItemResponse<T>> ReadItemAsync<T>(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RejectSerializerBypassTarget<T>();
        ItemRequestOptions? snapshot = SnapshotOptions(requestOptions, isWrite: false);
        cancellationToken.ThrowIfCancellationRequested();
        return RequireTypedContentAsync(inner.ReadItemAsync<T>(id, partitionKey, snapshot, cancellationToken), expectContent: true);
    }

    private static async Task<ItemResponse<T>> RequireTypedContentAsync<T>(Task<ItemResponse<T>> pending, bool expectContent)
    {
        ItemResponse<T> response = await pending.ConfigureAwait(false);
        if (expectContent && (int)response.StatusCode is >= 200 and <= 299
            && (response.Resource is null || (typeof(T).IsValueType && EqualityComparer<T>.Default.Equals(response.Resource, default!))))
            throw new ContentValidationException(ContentValidationFailure.MissingSignature, "A successful typed response has no nondefault document. Default-valued structs are not supported as content responses.");
        return response;
    }

    public override Task<ItemResponse<T>> DeleteItemAsync<T>(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RejectSerializerBypassTarget<T>();
        ItemRequestOptions? snapshot = SnapshotOptions(requestOptions);
        cancellationToken.ThrowIfCancellationRequested();
        return inner.DeleteItemAsync<T>(id, partitionKey, snapshot, cancellationToken);
    }

    public override Task<ResponseMessage> DeleteItemStreamAsync(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ItemRequestOptions? snapshot = SnapshotOptions(requestOptions);
        cancellationToken.ThrowIfCancellationRequested();
        return inner.DeleteItemStreamAsync(id, partitionKey, snapshot, cancellationToken);
    }

    public override async Task<ResponseMessage> CreateItemStreamAsync(Stream streamPayload, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireSigner();
        ArgumentNullException.ThrowIfNull(streamPayload);
        ItemRequestOptions? snapshot = SnapshotOptions(requestOptions);
        using RecyclableMemoryStream buffered = await processor.Buffers.ReadAsync(streamPayload, cancellationToken, processor.MaxDocumentBytes).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        using RecyclableMemoryStream signed = processor.Sign(buffered.GetReadOnlySequence(), replaceExistingSignature: true);
        cancellationToken.ThrowIfCancellationRequested();
        // Keep both owned streams alive through all SDK retries and response processing.
        ResponseMessage response = await inner.CreateItemStreamAsync(signed, partitionKey, snapshot, cancellationToken).ConfigureAwait(false);
        bool expectContent = snapshot?.EnableContentResponseOnWrite ?? contentResponseOnWrite;
        return await ValidateResponseAsync(response, expectContent, cancellationToken).ConfigureAwait(false);
    }

    public override async Task<ResponseMessage> ReadItemStreamAsync(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ItemRequestOptions? snapshot = SnapshotOptions(requestOptions, isWrite: false);
        cancellationToken.ThrowIfCancellationRequested();
        ResponseMessage response = await inner.ReadItemStreamAsync(id, partitionKey, snapshot, cancellationToken).ConfigureAwait(false);
        return await ValidateResponseAsync(response, expectContent: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ResponseMessage> ValidateResponseAsync(ResponseMessage response, bool expectContent, CancellationToken cancellationToken)
    {
        // Includes 304 and all service errors: preserve the exact response, headers, body and diagnostics.
        if (!response.IsSuccessStatusCode) return response;
        RecyclableMemoryStream? buffered = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            Stream? original = response.Content;
            if (original is null)
            {
                if (!expectContent) return response;
                throw new ContentValidationException(ContentValidationFailure.MissingSignature, "A successful item response has no signed document.");
            }
            buffered = await processor.Buffers.ReadAsync(original, cancellationToken, processor.MaxDocumentBytes).ConfigureAwait(false);
            if (buffered.Length == 0)
            {
                if (!expectContent)
                {
                    // Keep the original empty body owned by the response, not the unused copy.
                    buffered.Dispose();
                    buffered = null;
                    return response;
                }
                throw new ContentValidationException(ContentValidationFailure.MissingSignature, "A successful item response has an empty document.");
            }
            cancellationToken.ThrowIfCancellationRequested();
            processor.Validate(buffered.GetReadOnlySequence());
            cancellationToken.ThrowIfCancellationRequested();
            buffered.Position = 0;
            // Detach before disposing so a disposal failure cannot cause the response to dispose it twice.
            response.Content = null;
            original.Dispose();
            response.Content = buffered;
            buffered = null; // Ownership transfers only after the assignment succeeds.
            return response;
        }
        catch
        {
            buffered?.Dispose();
            response.Dispose();
            throw;
        }
    }

    private void RequireSigner()
    {
        if (!processor.CanSign)
            throw new ContentValidationException(ContentValidationFailure.SigningUnavailable, "This processor has no signing capability.");
    }

    private static void RejectSerializerBypassTarget<T>()
    {
        // The SDK's Stream target bypasses deserialization. Derived streams must also be refused.
        Type target = typeof(T);
        if (typeof(Stream).IsAssignableFrom(target)
            // Public DTOs from Cosmos 3.63.2 CosmosSerializerCore.IsInputTypeInternal.
            // GetSerializer<T> selects by exact generic type, not the runtime type of an object.
            // Array element checks in IsInputTypeInternal are for feed routing, not point targets.
            || target == typeof(AccountProperties)
            || target == typeof(DatabaseProperties)
            || target == typeof(ContainerProperties)
            || target == typeof(PermissionProperties)
            || target == typeof(StoredProcedureProperties)
            || target == typeof(TriggerProperties)
            || target == typeof(UserDefinedFunctionProperties)
            || target == typeof(UserProperties)
            || target == typeof(ConflictProperties)
            || target == typeof(ThroughputProperties)
            || target == typeof(ClientEncryptionKeyProperties))
            throw Unsupported();
    }

    private static ItemRequestOptions? SnapshotOptions(ItemRequestOptions? options, bool isWrite = true)
    {
        if (options is null) return null;
        if (options.GetType() != typeof(ItemRequestOptions)) throw Unsupported();
        ItemRequestOptions snapshot = (ItemRequestOptions)options.ShallowCopy();
        // Freeze lists before checking them: later caller mutation must not attach a write trigger.
        if (snapshot.PreTriggers is not null) snapshot.PreTriggers = snapshot.PreTriggers.ToArray();
        if (snapshot.PostTriggers is not null) snapshot.PostTriggers = snapshot.PostTriggers.ToArray();
        if (isWrite && (snapshot.PreTriggers?.Any() == true || snapshot.PostTriggers?.Any() == true))
            throw new NotSupportedException("Write requests with pre-trigger or post-trigger execution are not allowed with content validation.");
        if (snapshot.Properties is not null || snapshot.AddRequestHeaders is not null
            || snapshot.AvailabilityStrategy is not null)
            throw Unsupported();
        if (snapshot.DedicatedGatewayRequestOptions is { } gateway)
        {
            if (gateway.GetType() != typeof(DedicatedGatewayRequestOptions)) throw Unsupported();
            snapshot.DedicatedGatewayRequestOptions = new DedicatedGatewayRequestOptions
            {
                MaxIntegratedCacheStaleness = gateway.MaxIntegratedCacheStaleness,
                BypassIntegratedCache = gateway.BypassIntegratedCache
            };
        }
        if (snapshot.CosmosThresholdOptions is { } thresholds)
        {
            if (thresholds.GetType() != typeof(CosmosThresholdOptions)) throw Unsupported();
            snapshot.CosmosThresholdOptions = new CosmosThresholdOptions
            {
                NonPointOperationLatencyThreshold = thresholds.NonPointOperationLatencyThreshold,
                PointOperationLatencyThreshold = thresholds.PointOperationLatencyThreshold,
                RequestChargeThreshold = thresholds.RequestChargeThreshold,
                PayloadSizeThresholdInBytes = thresholds.PayloadSizeThresholdInBytes
            };
        }
        if (snapshot.ExcludeRegions is not null) snapshot.ExcludeRegions = new List<string>(snapshot.ExcludeRegions);
        return snapshot;
    }

    public override Task<int?> ReadThroughputAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return inner.ReadThroughputAsync(cancellationToken);
    }

    private static NotSupportedException Unsupported() => ContentValidationClient.Unsupported();
    public override Conflicts Conflicts => throw Unsupported();
    // Reject at the container boundary, before any typed/stream stored-procedure call can dispatch.
    public override Scripts Scripts => throw new NotSupportedException("Stored-procedure execution and scripts access are not allowed with content validation.");
    public override Task<ContainerResponse> ReadContainerAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> ReadContainerStreamAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> ReplaceContainerAsync(ContainerProperties containerProperties, ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> ReplaceContainerStreamAsync(ContainerProperties containerProperties, ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> DeleteContainerAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> DeleteContainerStreamAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ThroughputResponse> ReadThroughputAsync(RequestOptions requestOptions, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ThroughputResponse> ReplaceThroughputAsync(int throughput, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ThroughputResponse> ReplaceThroughputAsync(ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ItemResponse<T>> UpsertItemAsync<T>(T item, PartitionKey? partitionKey = null, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> UpsertItemStreamAsync(Stream streamPayload, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ItemResponse<T>> ReplaceItemAsync<T>(T item, string id, PartitionKey? partitionKey = null, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> ReplaceItemStreamAsync(Stream streamPayload, string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ItemResponse<T>> PatchItemAsync<T>(string id, PartitionKey partitionKey, IReadOnlyList<PatchOperation> patchOperations, PatchItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> PatchItemStreamAsync(string id, PartitionKey partitionKey, IReadOnlyList<PatchOperation> patchOperations, PatchItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<FeedResponse<T>> ReadManyItemsAsync<T>(IReadOnlyList<(string, PartitionKey)> items, ReadManyRequestOptions? readManyRequestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> ReadManyItemsStreamAsync(IReadOnlyList<(string, PartitionKey)> items, ReadManyRequestOptions? readManyRequestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override FeedIterator<T> GetItemQueryIterator<T>(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator<T> GetItemQueryIterator<T>(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator<T> GetItemQueryIterator<T>(FeedRange feedRange, QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator GetItemQueryStreamIterator(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator GetItemQueryStreamIterator(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator GetItemQueryStreamIterator(FeedRange feedRange, QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override IOrderedQueryable<T> GetItemLinqQueryable<T>(bool allowSynchronousQueryExecution = false, string? continuationToken = null, QueryRequestOptions? requestOptions = null, CosmosLinqSerializerOptions? linqSerializerOptions = null) => throw Unsupported();
    public override TransactionalBatch CreateTransactionalBatch(PartitionKey partitionKey) => throw Unsupported();
    public override Task<ResponseMessage> DeleteAllItemsByPartitionKeyStreamAsync(PartitionKey partitionKey, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<IReadOnlyList<FeedRange>> GetFeedRangesAsync(CancellationToken cancellationToken = default) => throw Unsupported();
    public override FeedIterator<T> GetChangeFeedIterator<T>(ChangeFeedStartFrom changeFeedStartFrom, ChangeFeedMode changeFeedMode, ChangeFeedRequestOptions? changeFeedRequestOptions = null) => throw Unsupported();
    public override FeedIterator GetChangeFeedStreamIterator(ChangeFeedStartFrom changeFeedStartFrom, ChangeFeedMode changeFeedMode, ChangeFeedRequestOptions? changeFeedRequestOptions = null) => throw Unsupported();
    public override ChangeFeedEstimator GetChangeFeedEstimator(string processorName, Container leaseContainer) => throw Unsupported();
    public override ChangeFeedProcessorBuilder GetChangeFeedEstimatorBuilder(string processorName, ChangesEstimationHandler estimationDelegate, TimeSpan? estimationPeriod = null) => throw Unsupported();
    public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilder<T>(string processorName, ChangesHandler<T> onChangesDelegate) => throw Unsupported();
    public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilder<T>(string processorName, ChangeFeedHandler<T> onChangesDelegate) => throw Unsupported();
    public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilder(string processorName, ChangeFeedStreamHandler onChangesDelegate) => throw Unsupported();
    public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilderWithManualCheckpoint<T>(string processorName, ChangeFeedHandlerWithManualCheckpoint<T> onChangesDelegate) => throw Unsupported();
    public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilderWithManualCheckpoint(string processorName, ChangeFeedStreamHandlerWithManualCheckpoint onChangesDelegate) => throw Unsupported();
    public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilderWithAllVersionsAndDeletes<T>(string processorName, ChangeFeedHandler<ChangeFeedItem<T>> onChangesDelegate) => throw Unsupported();
}