using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Fluent;

namespace CosmosContentValidation;

/// <summary>Guarded database navigation; resource-returning management is intentionally blocked.</summary>
/// <remarks>DatabaseResponse.Database would expose an unguarded SDK database, so even ReadAsync is blocked.</remarks>
public sealed class ContentValidationDatabase : Database
{
    private readonly ContentValidationClient client;
    private readonly Database inner;
    private readonly ContentValidationProcessor processor;
    private readonly bool contentResponseOnWrite;

    internal ContentValidationDatabase(ContentValidationClient client, Database inner, ContentValidationProcessor processor, bool contentResponseOnWrite)
    {
        this.client = client;
        this.inner = inner;
        this.processor = processor;
        this.contentResponseOnWrite = contentResponseOnWrite;
    }

    public override string Id => inner.Id;
    public override CosmosClient Client => client;
    public override Container GetContainer(string id) => new ContentValidationContainer(this, inner.GetContainer(id), processor, contentResponseOnWrite);
    public override Task<int?> ReadThroughputAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return inner.ReadThroughputAsync(cancellationToken);
    }

    private static NotSupportedException Unsupported() => ContentValidationClient.Unsupported();
    public override Task<DatabaseResponse> ReadAsync(RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<DatabaseResponse> DeleteAsync(RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> ReadStreamAsync(RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> DeleteStreamAsync(RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ThroughputResponse> ReadThroughputAsync(RequestOptions requestOptions, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ThroughputResponse> ReplaceThroughputAsync(int throughput, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ThroughputResponse> ReplaceThroughputAsync(ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> CreateContainerAsync(ContainerProperties containerProperties, ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> CreateContainerAsync(ContainerProperties containerProperties, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> CreateContainerAsync(string id, string partitionKeyPath, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> CreateContainerIfNotExistsAsync(ContainerProperties containerProperties, ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> CreateContainerIfNotExistsAsync(ContainerProperties containerProperties, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ContainerResponse> CreateContainerIfNotExistsAsync(string id, string partitionKeyPath, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> CreateContainerStreamAsync(ContainerProperties containerProperties, ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> CreateContainerStreamAsync(ContainerProperties containerProperties, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override User GetUser(string id) => throw Unsupported();
    public override Task<UserResponse> CreateUserAsync(string id, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<UserResponse> UpsertUserAsync(string id, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override FeedIterator<T> GetContainerQueryIterator<T>(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator<T> GetContainerQueryIterator<T>(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator GetContainerQueryStreamIterator(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator GetContainerQueryStreamIterator(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator<T> GetUserQueryIterator<T>(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator<T> GetUserQueryIterator<T>(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override ContainerBuilder DefineContainer(string name, string partitionKeyPath) => throw Unsupported();
    public override ClientEncryptionKey GetClientEncryptionKey(string id) => throw Unsupported();
    public override FeedIterator<ClientEncryptionKeyProperties> GetClientEncryptionKeyQueryIterator(QueryDefinition? queryDefinition = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override Task<ClientEncryptionKeyResponse> CreateClientEncryptionKeyAsync(ClientEncryptionKeyProperties clientEncryptionKeyProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
}