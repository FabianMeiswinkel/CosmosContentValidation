using Microsoft.Azure.Cosmos;

namespace CosmosContentValidation;

/// <summary>Public-surface-only request-option validation and detached snapshots.</summary>
internal static class ContentValidationRequestOptions
{
    internal static QueryRequestOptions? Snapshot(QueryRequestOptions? options, bool stream)
    {
        if (options is null) return null;
        if (options.GetType() != typeof(QueryRequestOptions)) throw Unsupported();
        RequestOptions inherited = options;
        RejectUnsafeBaseOptions(inherited);
        if (options.QueryTextMode != new QueryRequestOptions().QueryTextMode)
            throw Unsupported();
        if (options.PopulateIndexMetrics == true || options.PopulateQueryAdvice == true)
            throw new NotSupportedException("Protected query responses cannot preserve requested index metrics or query advice.");
        return new QueryRequestOptions
        {
            ConsistencyLevel = options.ConsistencyLevel,
            DedicatedGatewayRequestOptions = Copy(options.DedicatedGatewayRequestOptions),
            EnableLowPrecisionOrderBy = options.EnableLowPrecisionOrderBy,
            EnableOptimisticDirectExecution = options.EnableOptimisticDirectExecution,
            EnableScanInQuery = options.EnableScanInQuery,
            FullTextScoreScope = options.FullTextScoreScope,
            MaxBufferedItemCount = options.MaxBufferedItemCount,
            MaxConcurrency = options.MaxConcurrency,
            MaxItemCount = options.MaxItemCount,
            PartitionKey = options.PartitionKey,
            PopulateIndexMetrics = options.PopulateIndexMetrics,
            PopulateQueryAdvice = options.PopulateQueryAdvice,
            QueryTextMode = options.QueryTextMode,
            ReadConsistencyStrategy = options.ReadConsistencyStrategy,
            ResponseContinuationTokenLimitInKb = options.ResponseContinuationTokenLimitInKb,
            SessionToken = options.SessionToken,
            PriorityLevel = inherited.PriorityLevel,
            ThroughputBucket = inherited.ThroughputBucket,
            ExcludeRegions = inherited.ExcludeRegions is null ? null : new List<string>(inherited.ExcludeRegions),
            CosmosThresholdOptions = Copy(inherited.CosmosThresholdOptions)
        };
    }

    internal static ChangeFeedRequestOptions? Snapshot(ChangeFeedRequestOptions? options)
    {
        if (options is null) return null;
        RequestOptions inherited = options;
        RejectUnsafeBaseOptions(inherited);
        return new ChangeFeedRequestOptions
        {
            PageSizeHint = options.PageSizeHint,
            ReadConsistencyStrategy = options.ReadConsistencyStrategy,
            PriorityLevel = inherited.PriorityLevel,
            ThroughputBucket = inherited.ThroughputBucket,
            ExcludeRegions = inherited.ExcludeRegions is null ? null : new List<string>(inherited.ExcludeRegions),
            CosmosThresholdOptions = Copy(inherited.CosmosThresholdOptions)
        };
    }

    private static void RejectUnsafeBaseOptions(RequestOptions options)
    {
        if (options.Properties is not null || options.AddRequestHeaders is not null
            || options.AvailabilityStrategy is not null || options.IfMatchEtag is not null
            || options.IfNoneMatchEtag is not null)
            throw Unsupported();
    }

    private static DedicatedGatewayRequestOptions? Copy(DedicatedGatewayRequestOptions? options)
    {
        if (options is null) return null;
        if (options.GetType() != typeof(DedicatedGatewayRequestOptions)) throw Unsupported();
        return new DedicatedGatewayRequestOptions
        {
            MaxIntegratedCacheStaleness = options.MaxIntegratedCacheStaleness,
            BypassIntegratedCache = options.BypassIntegratedCache
        };
    }

    private static CosmosThresholdOptions? Copy(CosmosThresholdOptions? options)
    {
        if (options is null) return null;
        if (options.GetType() != typeof(CosmosThresholdOptions)) throw Unsupported();
        return new CosmosThresholdOptions
        {
            NonPointOperationLatencyThreshold = options.NonPointOperationLatencyThreshold,
            PointOperationLatencyThreshold = options.PointOperationLatencyThreshold,
            RequestChargeThreshold = options.RequestChargeThreshold,
            PayloadSizeThresholdInBytes = options.PayloadSizeThresholdInBytes
        };
    }

    private static NotSupportedException Unsupported() => new(
        "This request option is not supported by content-validation query or change-feed infrastructure.");
}
