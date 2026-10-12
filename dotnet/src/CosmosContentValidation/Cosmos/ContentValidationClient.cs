using System.Reflection;
using System.Runtime.CompilerServices;
using Azure.Core;
using Microsoft.Azure.Cosmos;

[assembly: InternalsVisibleTo("CosmosContentValidation.Tests")]

namespace CosmosContentValidation;

/// <summary>A fail-closed Cosmos SDK client for preprovisioned containers.</summary>
/// <remarks>
/// PR1 supports point create/read/delete (typed and stream), guarded navigation, account reads,
/// and scalar throughput reads. Resource-returning management, queries, feeds, bulk, batch,
/// replace, upsert, patch, scripts, conflicts and LINQ are deliberately unavailable.
/// Before use, independently check that every target container's actual partition-key paths
/// exactly match the processor's configured paths. No provisioning or key I/O is performed here.
/// The client owns only its inner SDK client; the processor and providers remain caller-owned.
/// Options are snapshotted, not owned: do not mutate them concurrently with a factory call.
/// Only application/region selection, connection mode, consistency, timeout, retry limits,
/// endpoint limiting and write-response-content settings are accepted. Other nondefault settings
/// are rejected, not silently ignored. Custom serializers/handlers/transports are not accepted.
/// </remarks>
public sealed class ContentValidationClient : CosmosClient
{
    // This SDK property's delegate signature contains certificate types. Read only its presence
    // as an object so rejecting custom TLS validation does not couple this assembly to crypto.
    // Fail closed if the pinned SDK surface changes; never invoke the callback.
    private static readonly PropertyInfo CertificateValidationCallbackProperty =
        typeof(CosmosClientOptions).GetProperty(nameof(CosmosClientOptions.ServerCertificateCustomValidationCallback))
        ?? throw new InvalidOperationException("The SDK certificate-validation option is unavailable.");
    private readonly CosmosClient inner;
    private readonly ContentValidationProcessor processor;
    private readonly CosmosClientOptions configuration;
    private int disposed;

    internal ContentValidationClient(CosmosClient inner, ContentValidationProcessor processor, CosmosClientOptions? options = null)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.processor = processor ?? throw new ArgumentNullException(nameof(processor));
        configuration = ValidateAndCopyOptions(options);
    }

    /// <summary>Creates and owns an SDK client with the validating serializer installed.</summary>
    public static ContentValidationClient Create(string endpoint, string key, ContentValidationProcessor processor, CosmosClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(processor);
        CosmosClientOptions configuration = ValidateAndCopyOptions(options);
        CosmosClientOptions sdkOptions = CopyAllowedOptions(configuration);
        sdkOptions.Serializer = new ContentValidationSerializer(processor);
        return new ContentValidationClient(new CosmosClient(endpoint, key, sdkOptions), processor, configuration);
    }

    /// <summary>Uses a caller-owned credential; acquiring tokens remains the SDK's responsibility.</summary>
    public static ContentValidationClient Create(string endpoint, TokenCredential credential, ContentValidationProcessor processor, CosmosClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(processor);
        ArgumentNullException.ThrowIfNull(credential);
        CosmosClientOptions configuration = ValidateAndCopyOptions(options);
        CosmosClientOptions sdkOptions = CopyAllowedOptions(configuration);
        sdkOptions.Serializer = new ContentValidationSerializer(processor);
        return new ContentValidationClient(new CosmosClient(endpoint, credential, sdkOptions), processor, configuration);
    }

    /// <summary>Returns a detached snapshot. Mutating it cannot reconfigure the protected client.</summary>
    public override CosmosClientOptions ClientOptions
    {
        get
        {
            CosmosClientOptions snapshot = CopyAllowedOptions(configuration);
            snapshot.Serializer = new ContentValidationSerializer(processor);
            return snapshot;
        }
    }

    public override Uri Endpoint => inner.Endpoint;
    public override CosmosResponseFactory ResponseFactory => inner.ResponseFactory;
    public override Task<AccountProperties> ReadAccountAsync() => inner.ReadAccountAsync();
    public override Database GetDatabase(string id) => new ContentValidationDatabase(this, inner.GetDatabase(id), processor, configuration.EnableContentResponseOnWrite != false);
    public override Container GetContainer(string databaseId, string containerId) => GetDatabase(databaseId).GetContainer(containerId);

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref disposed, 1) == 0)
            inner.Dispose();
        // The SDK's protected decorator constructor does not initialize ClientContext.
        // Calling base.Dispose(bool) would dereference that uninitialized context.
    }

    internal static NotSupportedException Unsupported() => new("This operation is not supported by the PR1 content-validation client. Use preprovisioned containers and point create/read/delete only.");

    private static CosmosClientOptions ValidateAndCopyOptions(CosmosClientOptions? options)
    {
        if (options is null) return new CosmosClientOptions();
        if (options.GetType() != typeof(CosmosClientOptions)) throw Unsupported();
        CosmosClientOptions defaults = new();
        if (options.AllowBulkExecution || options.Serializer is not null || options.SerializerOptions is not null
            || options.UseSystemTextJsonSerializerWithOptions is not null || options.CustomHandlers.Count != 0
            || options.HttpClientFactory is not null || options.WebProxy is not null
            || CertificateValidationCallbackProperty.GetValue(options) is not null || options.FaultInjector is not null
            || options.AvailabilityStrategy is not null || options.AccountInitializationCustomEndpoints is not null
            || options.GatewayModeMaxConnectionLimit != defaults.GatewayModeMaxConnectionLimit
            || options.TokenCredentialBackgroundRefreshInterval != defaults.TokenCredentialBackgroundRefreshInterval
            || options.ReadConsistencyStrategy != defaults.ReadConsistencyStrategy || options.PriorityLevel != defaults.PriorityLevel
            || options.IdleTcpConnectionTimeout != defaults.IdleTcpConnectionTimeout
            || options.OpenTcpConnectionTimeout != defaults.OpenTcpConnectionTimeout
            || options.MaxRequestsPerTcpConnection != defaults.MaxRequestsPerTcpConnection
            || options.MaxTcpConnectionsPerEndpoint != defaults.MaxTcpConnectionsPerEndpoint
            || options.PortReuseMode != defaults.PortReuseMode
            || options.EnableTcpConnectionEndpointRediscovery != defaults.EnableTcpConnectionEndpointRediscovery
            || options.ThroughputBucket != defaults.ThroughputBucket
            || !IsDefaultTelemetry(options.CosmosClientTelemetryOptions, defaults.CosmosClientTelemetryOptions))
            throw Unsupported();
        return CopyAllowedOptions(options);
    }

    private static bool IsDefaultTelemetry(CosmosClientTelemetryOptions? value, CosmosClientTelemetryOptions defaults)
    {
        if (value is null || value.GetType() != typeof(CosmosClientTelemetryOptions)) return false;
        CosmosThresholdOptions? thresholds = value.CosmosThresholdOptions;
        CosmosThresholdOptions expected = defaults.CosmosThresholdOptions;
        return value.DisableSendingMetricsToService == defaults.DisableSendingMetricsToService
            && value.DisableDistributedTracing == defaults.DisableDistributedTracing
            && value.QueryTextMode == defaults.QueryTextMode
            && thresholds is not null && thresholds.GetType() == typeof(CosmosThresholdOptions)
            && thresholds.NonPointOperationLatencyThreshold == expected.NonPointOperationLatencyThreshold
            && thresholds.PointOperationLatencyThreshold == expected.PointOperationLatencyThreshold
            && thresholds.RequestChargeThreshold == expected.RequestChargeThreshold
            && thresholds.PayloadSizeThresholdInBytes == expected.PayloadSizeThresholdInBytes;
    }

    private static CosmosClientOptions CopyAllowedOptions(CosmosClientOptions source)
    {
        CosmosClientOptions copy = new()
        {
        ApplicationRegion = source.ApplicationRegion,
        ApplicationPreferredRegions = source.ApplicationPreferredRegions is null ? null : new List<string>(source.ApplicationPreferredRegions).AsReadOnly(),
        ConnectionMode = source.ConnectionMode,
        ConsistencyLevel = source.ConsistencyLevel,
        RequestTimeout = source.RequestTimeout,
        MaxRetryAttemptsOnRateLimitedRequests = source.MaxRetryAttemptsOnRateLimitedRequests,
        MaxRetryWaitTimeOnRateLimitedRequests = source.MaxRetryWaitTimeOnRateLimitedRequests,
        LimitToEndpoint = source.LimitToEndpoint,
        EnableContentResponseOnWrite = source.EnableContentResponseOnWrite
        };
        // The SDK default getter is null, but its ApplicationName setter rejects null.
        if (source.ApplicationName is not null) copy.ApplicationName = source.ApplicationName;
        return copy;
    }

    public override Task<DatabaseResponse> CreateDatabaseAsync(string id, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<DatabaseResponse> CreateDatabaseAsync(string id, ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<DatabaseResponse> CreateDatabaseIfNotExistsAsync(string id, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<DatabaseResponse> CreateDatabaseIfNotExistsAsync(string id, ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override Task<ResponseMessage> CreateDatabaseStreamAsync(DatabaseProperties databaseProperties, int? throughput = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unsupported();
    public override FeedIterator<T> GetDatabaseQueryIterator<T>(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator<T> GetDatabaseQueryIterator<T>(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator GetDatabaseQueryStreamIterator(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
    public override FeedIterator GetDatabaseQueryStreamIterator(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unsupported();
}