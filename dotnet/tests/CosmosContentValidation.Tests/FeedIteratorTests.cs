using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CosmosContentValidation.Sample.Providers;
using Microsoft.Azure.Cosmos;
using Microsoft.IO;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class FeedIteratorTests
{
    private const string Endpoint = "https://localhost:8081";
    private const string Key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public async Task StreamPageReplaysExactEnvelopeAndDelegatesMetadataUntilDisposed()
    {
        using Harness harness = new();
        byte[] page = harness.Page(harness.Sign("one", 1), harness.Sign("two", 2));
        TrackingStream originalBody = new(page, seekable: false);
        TrackingResponse original = Response(HttpStatusCode.OK, originalBody);
        original.Headers.Add("x-ms-activity-id", "activity");
        original.Headers.Add("x-ms-continuation", "continuation");
        FakeIterator inner = new(original);
        ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        ResponseMessage response = await iterator.ReadNextAsync();

        Assert.IsType<ContentValidationResponseMessage>(response);
        Assert.Equal(original.StatusCode, response.StatusCode);
        Assert.Same(original.Headers, response.Headers);
        Assert.Equal("activity", response.Headers.ActivityId);
        Assert.Equal("continuation", response.ContinuationToken);
        Assert.Equal(original.ErrorMessage, response.ErrorMessage);
        Assert.Same(original.RequestMessage, response.RequestMessage);
        Assert.Equal(original.Diagnostics.ToString(), response.Diagnostics.ToString());
        Assert.Equal(original.IsSuccessStatusCode, response.IsSuccessStatusCode);
        RecyclableMemoryStream replay = Assert.IsType<RecyclableMemoryStream>(response.Content);
        Assert.Equal(0, replay.Position);
        Assert.Equal(page, replay.GetReadOnlySequence().ToArray());
        Assert.Equal(0, original.DisposeCalls);
        Assert.Equal(0, originalBody.DisposeCalls);
        Assert.True(harness.Processor.Buffers.InUseBytes > 0);

        response.Dispose();
        response.Dispose();
        Assert.Equal(1, original.DisposeCalls);
        Assert.Equal(1, originalBody.DisposeCalls);
        Assert.False(replay.CanRead);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
        iterator.Dispose();
        iterator.Dispose();
        Assert.Equal(1, inner.DisposeCalls);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task LazyOverrideQueryBodyIsDisposedByFacade()
    {
        using Harness harness = new();
        TrackingStream nativeBody = new(harness.Page());
        LazyContentResponse original = new(nativeBody);
        using ContentValidationFeedIterator iterator = new(new FakeIterator(original), harness.Processor);

        ResponseMessage response = await iterator.ReadNextAsync();

        Assert.IsType<ContentValidationResponseMessage>(response);
        Assert.Equal(0, nativeBody.DisposeCalls);
        Assert.True(response.Content.CanRead);
        response.Dispose();
        Assert.Equal(1, nativeBody.DisposeCalls);
        Assert.Equal(1, original.DisposeCalls);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task EmptyDocumentsAndUnrelatedEnvelopeArraysAreValid()
    {
        using Harness harness = new();
        byte[] page = "{\"meta\":[1,{\"nested\":[]}],\"Documents\":[],\"_count\":0}"u8.ToArray();
        FakeIterator inner = new(Response(HttpStatusCode.OK, new TrackingStream(page)));
        using ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        using ResponseMessage response = await iterator.ReadNextAsync();

        Assert.Equal(page, await ReadAll(response.Content));
        Assert.True(harness.Processor.Buffers.InUseBytes > 0);
    }

    [Fact]
    public async Task ChangeFeedOnlyLsnIsUnauthenticatedButPointDocumentsStillRejectIt()
    {
        using Harness harness = new();
        JsonObject document = JsonNode.Parse(harness.Sign("one", 1))!.AsObject();
        document["_lsn"] = 42;
        byte[] page = harness.Page(document.ToJsonString());
        using ContentValidationFeedIterator iterator = new(
            new FakeIterator(Response(HttpStatusCode.OK, new TrackingStream(page))), harness.Processor);

        using ResponseMessage response = await iterator.ReadNextAsync();

        Assert.Equal(page, await ReadAll(response.Content));
        Assert.Equal(ContentValidationFailure.InvalidSignature,
            Assert.Throws<ContentValidationException>(() => harness.Processor.Validate(
                new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(document.ToJsonString())))).Failure);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"documents\":[]}")]
    [InlineData("{\"Documents\":null}")]
    [InlineData("{\"Documents\":{}}")]
    [InlineData("{\"Documents\":[],\"Documents\":[]}")]
    [InlineData("{\"Documents\":[],\"Doc\\u0075ments\":[]}")]
    [InlineData("{\"Documents\":[],\"meta\":1,\"meta\":2}")]
    [InlineData("[]")]
    [InlineData("{\"Documents\":[]} null")]
    public void FeedEnvelopeShapeCasingDuplicatesAndTrailingJsonAreRejected(string page)
    {
        using Harness harness = new();
        byte[] bytes = Encoding.UTF8.GetBytes(page);
        byte[] snapshot = (byte[])bytes.Clone();

        ContentValidationException failure = Assert.Throws<ContentValidationException>(
            () => harness.Processor.ValidateFeedPage(new ReadOnlySequence<byte>(bytes)));

        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Equal(snapshot, bytes);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void FeedPageRejectsMalformedUtf8AndOversizedPageWithoutChangingInput()
    {
        using Harness harness = new();
        byte[] invalid = [.. "{\"Documents\":[],\"meta\":\""u8, 0xFF, .. "\"}"u8];
        byte[] snapshot = (byte[])invalid.Clone();
        Assert.Equal(ContentValidationFailure.InvalidDocument,
            Assert.Throws<ContentValidationException>(() => harness.Processor.ValidateFeedPage(new(invalid))).Failure);
        Assert.Equal(snapshot, invalid);

        byte[] oversized = new byte[harness.Processor.Buffers.MaxBufferBytes + 1];
        Assert.Equal(ContentValidationFailure.PayloadTooLarge,
            Assert.Throws<ContentValidationException>(() => harness.Processor.ValidateFeedPage(new(oversized))).Failure);
    }

    [Fact]
    public void FeedPageEnforcesTheRawPerDocumentLimitIncludingIgnoredMetadata()
    {
        using Harness harness = new(new ContentValidationOptions { MaxDocumentBytes = 1024, MaxBufferedBytes = 4096 });
        JsonObject document = JsonNode.Parse(harness.Sign("one", 1))!.AsObject();
        document["_etag"] = new string('x', 900);
        byte[] page = harness.Page(document.ToJsonString());
        Assert.True(page.Length < harness.Processor.Buffers.MaxBufferBytes);

        ContentValidationException failure = Assert.Throws<ContentValidationException>(
            () => harness.Processor.ValidateFeedPage(new(page)));

        Assert.Equal(ContentValidationFailure.PayloadTooLarge, failure.Failure);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidFirstOrLaterDocumentDisposesResponsePoisonsIteratorAndMapsNothing(bool later)
    {
        using Harness harness = new();
        string valid = harness.Sign("valid", 1);
        JsonObject invalid = JsonNode.Parse(harness.Sign("invalid", 2))!.AsObject();
        invalid["value"] = 99;
        string[] documents = later ? [valid, invalid.ToJsonString()] : [invalid.ToJsonString(), valid];
        TrackingResponse original = Response(HttpStatusCode.OK, new TrackingStream(harness.Page(documents)));
        FakeIterator inner = new(original);
        ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() => iterator.ReadNextAsync());

        Assert.Equal(ContentValidationFailure.InvalidSignature, failure.Failure);
        Assert.Equal(1, original.DisposeCalls);
        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
        await Assert.ThrowsAsync<InvalidOperationException>(() => iterator.ReadNextAsync());
        iterator.Dispose();
        Assert.Equal(1, inner.DisposeCalls);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidLaterPageFailsInsteadOfBeingSkipped(bool typed)
    {
        using Harness harness = new(createClient: typed);
        string valid = harness.Sign("valid", 1);
        JsonObject invalid = JsonNode.Parse(harness.Sign("invalid", 2))!.AsObject();
        if (typed) invalid.Remove(ContentValidationProcessor.SignaturePropertyName);
        else invalid["value"] = 99;
        FakeIterator inner = new(
            Response(HttpStatusCode.OK, new TrackingStream(harness.Page(valid))),
            Response(HttpStatusCode.OK, new TrackingStream(harness.Page(invalid.ToJsonString()))));

        if (typed)
        {
            ContentValidationFeedIterator<TypedItem> iterator = new(inner, harness.Processor, harness.Client!.ResponseFactory);
            FeedResponse<TypedItem> first = await iterator.ReadNextAsync();
            Assert.Equal("valid", Assert.Single(first).Id);
            ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() => iterator.ReadNextAsync());
            Assert.Equal(ContentValidationFailure.MissingSignature, failure.Failure);
            Assert.False(iterator.HasMoreResults);
            iterator.Dispose();
        }
        else
        {
            ContentValidationFeedIterator iterator = new(inner, harness.Processor);
            using ResponseMessage first = await iterator.ReadNextAsync();
            ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() => iterator.ReadNextAsync());
            Assert.Equal(ContentValidationFailure.InvalidSignature, failure.Failure);
            Assert.False(iterator.HasMoreResults);
            iterator.Dispose();
        }
        Assert.Equal(1, inner.DisposeCalls);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(304)]
    [InlineData(404)]
    [InlineData(429)]
    public async Task NotModifiedAndErrorsAreReturnedUntouchedWithoutReadingOrPoisoning(int status)
    {
        using Harness harness = new();
        TrackingStream body = new("not a feed page"u8.ToArray());
        TrackingResponse original = Response((HttpStatusCode)status, body);
        FakeIterator inner = new(original, Response(HttpStatusCode.OK, new TrackingStream(harness.Page())));
        using ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        ResponseMessage returned = await iterator.ReadNextAsync();

        Assert.Same(original, returned);
        Assert.Same(body, returned.Content);
        Assert.Equal(0, body.ReadCalls);
        Assert.True(iterator.HasMoreResults);
        returned.Dispose();
        Assert.Equal(1, original.DisposeCalls);
        using ResponseMessage empty = await iterator.ReadNextAsync();
        Assert.True(empty.IsSuccessStatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task MissingSuccessfulBodyPoisonsAndDisposesEverything(string? content)
    {
        using Harness harness = new();
        TrackingResponse response = Response(HttpStatusCode.OK,
            content is null ? null : new TrackingStream(Encoding.UTF8.GetBytes(content)));
        FakeIterator inner = new(response);
        ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() => iterator.ReadNextAsync());

        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task CancellationDuringPageCopyDisposesResponseAndPoisons()
    {
        using Harness harness = new();
        using CancellationTokenSource cancellation = new();
        TrackingStream body = new(harness.Page()) { BeforeFirstRead = cancellation.Cancel };
        TrackingResponse response = Response(HttpStatusCode.OK, body);
        FakeIterator inner = new(response);
        ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => iterator.ReadNextAsync(cancellation.Token));

        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, body.DisposeCalls);
        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task PreCancellationDoesNotCallOrPoisonInnerIterator()
    {
        using Harness harness = new();
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        FakeIterator inner = new(Response(HttpStatusCode.OK, new TrackingStream(harness.Page())));
        using ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => iterator.ReadNextAsync(cancellation.Token));

        Assert.Equal(0, inner.ReadCalls);
        Assert.True(iterator.HasMoreResults);
    }

    [Fact]
    public async Task PreResponseTransportFailureCanBeRetried()
    {
        using Harness harness = new();
        TrackingResponse response = Response(HttpStatusCode.OK, new TrackingStream(harness.Page()));
        ThrowOnceIterator inner = new(response);
        using ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        await Assert.ThrowsAsync<IOException>(() => iterator.ReadNextAsync());

        Assert.True(iterator.HasMoreResults);
        Assert.Equal(0, inner.DisposeCalls);
        using ResponseMessage retried = await iterator.ReadNextAsync();
        Assert.IsType<ContentValidationResponseMessage>(retried);
        Assert.True(retried.IsSuccessStatusCode);
    }

    [Fact]
    public async Task StreamCancellationAfterErrorPageAcquisitionDisposesAndPoisons()
    {
        using Harness harness = new();
        using CancellationTokenSource cancellation = new();
        TrackingResponse response = Response(HttpStatusCode.TooManyRequests, new TrackingStream("error"u8.ToArray()));
        FakeIterator inner = new(response) { AfterRead = cancellation.Cancel };
        ContentValidationFeedIterator iterator = new(inner, harness.Processor);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => iterator.ReadNextAsync(cancellation.Token));

        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
    }

    [Fact]
    public async Task TypedFactoryValidatesWholeArrayBeforeConstructingAnyTarget()
    {
        using Harness harness = new(createClient: true);
        string first = harness.Sign("first", 1);
        JsonObject later = JsonNode.Parse(harness.Sign("later", 2))!.AsObject();
        later["value"] = 3;
        TrackingStream body = new(harness.Page(first, later.ToJsonString()));
        TrackingResponse response = Response(HttpStatusCode.OK, body);
        FakeIterator inner = new(response);
        ConstructionProbe.Constructions = 0;
        ContentValidationFeedIterator<ConstructionProbe> iterator = new(inner, harness.Processor, harness.Client!.ResponseFactory);

        ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() => iterator.ReadNextAsync());

        Assert.Equal(ContentValidationFailure.InvalidSignature, failure.Failure);
        Assert.Equal(0, ConstructionProbe.Constructions);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, body.DisposeCalls);
        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task TypedSuccessfulMissingBodyFailsClosedAndPoisons()
    {
        using Harness harness = new(createClient: true);
        TrackingResponse response = Response(HttpStatusCode.OK);
        FakeIterator inner = new(response);
        ContentValidationFeedIterator<TypedItem> iterator = new(inner, harness.Processor, harness.Client!.ResponseFactory);

        ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() => iterator.ReadNextAsync());

        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
        await Assert.ThrowsAsync<InvalidOperationException>(() => iterator.ReadNextAsync());
    }

    [Fact]
    public async Task TypedFactoryReturnsNativeFeedResponseWithValidatedTargets()
    {
        using Harness harness = new(createClient: true);
        TrackingStream body = new(Encoding.UTF8.GetBytes("{\"meta\":[1,2],\"Documents\":["
            + harness.Sign("one", 1) + "," + harness.Sign("two", 2) + "],\"after\":[3]}"));
        FakeIterator inner = new(Response(HttpStatusCode.OK, body));
        using ContentValidationFeedIterator<TypedItem> iterator = new(inner, harness.Processor, harness.Client!.ResponseFactory);

        FeedResponse<TypedItem> response = await iterator.ReadNextAsync();

        Assert.Equal(2, response.Count);
        Assert.Equal(new[] { "one", "two" }, response.Select(item => item.Id));
        Assert.Equal(new[] { 1, 2 }, response.Select(item => item.Value));
        Assert.Equal(2, harness.Verifier.VerifyCalls);
        Assert.Equal(1, body.DisposeCalls);
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task TypedFactoryRejectsMissingDocumentsEvenWhenAnotherArrayContainsSignedItems()
    {
        using Harness harness = new(createClient: true);
        byte[] page = Encoding.UTF8.GetBytes("{\"other\":[" + harness.Sign("one", 1) + "]}");
        TrackingResponse response = Response(HttpStatusCode.OK, new TrackingStream(page));
        FakeIterator inner = new(response);
        ContentValidationFeedIterator<ConstructionProbe> iterator = new(inner, harness.Processor, harness.Client!.ResponseFactory);
        ConstructionProbe.Constructions = 0;

        ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() => iterator.ReadNextAsync());

        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Equal(0, ConstructionProbe.Constructions);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
    }

    [Fact]
    public void TypedSdkOwnedTargetIsRejectedBeforeIteratorUse()
    {
        using Harness harness = new(createClient: true);
        using FakeIterator inner = new(Response(HttpStatusCode.OK,
            new TrackingStream("{\"Documents\":[{\"id\":\"unsigned\",\"pk\":\"p\"}]}"u8.ToArray())));
        Assert.Throws<NotSupportedException>(() => new ContentValidationFeedIterator<DatabaseProperties>(
            inner, harness.Processor, harness.Client!.ResponseFactory));
        Assert.Equal(0, inner.ReadCalls);
    }

    [Fact]
    public void FeedProviderInvariantFailureIsNotTranslatedToInvalidDocument()
    {
        using Harness harness = new();
        ContentValidationProcessor reader = new(new(), new MismatchedResolver(),
            new UnsafeJcsCanonicalizer(), new UnsafeSha256ContentHasher());

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(
            () => reader.ValidateFeedPage(new(harness.Page(harness.Sign("one", 1)))));

        Assert.Contains("different key identifier", failure.Message);
    }

    [Fact]
    public async Task TypedNotModifiedProducesNativeEmptyFeedResponse()
    {
        using Harness harness = new(createClient: true);
        FakeIterator inner = new(Response(HttpStatusCode.NotModified));
        using ContentValidationFeedIterator<TypedItem> iterator = new(inner, harness.Processor, harness.Client!.ResponseFactory);

        FeedResponse<TypedItem> response = await iterator.ReadNextAsync();

        Assert.Empty(response);
        Assert.Equal(0, response.Count);
    }

    [Fact]
    public async Task TypedCancellationAfterMaterializationPoisonsIterator()
    {
        using Harness harness = new(createClient: true);
        using CancellationTokenSource cancellation = new();
        CancellingProbe.Cancellation = cancellation;
        FakeIterator inner = new(Response(HttpStatusCode.OK,
            new TrackingStream(harness.Page(harness.Sign("one", 1)))));
        ContentValidationFeedIterator<CancellingProbe> iterator = new(inner, harness.Processor, harness.Client!.ResponseFactory);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => iterator.ReadNextAsync(cancellation.Token));

        Assert.Equal(1, inner.DisposeCalls);
        Assert.False(iterator.HasMoreResults);
        CancellingProbe.Cancellation = null;
    }

    [Fact]
    public void QueryAndChangeFeedOptionPublicSurfacesArePinned()
    {
        string[] query =
        [
            "AddRequestHeaders", "AvailabilityStrategy", "ConsistencyLevel", "CosmosThresholdOptions",
            "DedicatedGatewayRequestOptions", "EnableLowPrecisionOrderBy", "EnableOptimisticDirectExecution",
            "EnableScanInQuery", "ExcludeRegions", "FullTextScoreScope", "IfMatchEtag", "IfNoneMatchEtag",
            "MaxBufferedItemCount", "MaxConcurrency", "MaxItemCount", "PartitionKey", "PopulateIndexMetrics",
            "PopulateQueryAdvice", "PriorityLevel", "Properties", "QueryTextMode", "ReadConsistencyStrategy",
            "ResponseContinuationTokenLimitInKb", "SessionToken", "ThroughputBucket"
        ];
        string[] change =
        [
            "AddRequestHeaders", "AvailabilityStrategy", "CosmosThresholdOptions", "ExcludeRegions",
            "IfMatchEtag", "IfNoneMatchEtag", "PageSizeHint", "PriorityLevel", "Properties",
            "ReadConsistencyStrategy", "ThroughputBucket"
        ];
        Assert.Equal(query.Order(), typeof(QueryRequestOptions).GetProperties().Select(property => property.Name).Order());
        Assert.Equal(change.Order(), typeof(ChangeFeedRequestOptions).GetProperties().Select(property => property.Name).Order());
    }

    [Fact]
    public void QueryOptionsAreDetachedAndUnsupportedStreamMetadataIsRejectedOnlyWhenRequested()
    {
        List<string> regions = [Regions.EastUS];
        QueryRequestOptions options = new()
        {
            MaxItemCount = 7,
            MaxConcurrency = 3,
            MaxBufferedItemCount = 11,
            ResponseContinuationTokenLimitInKb = 4,
            SessionToken = "session",
            PartitionKey = new PartitionKey("p"),
            PopulateIndexMetrics = false,
            PopulateQueryAdvice = false,
            PriorityLevel = PriorityLevel.High,
            ThroughputBucket = 2,
            ExcludeRegions = regions,
            DedicatedGatewayRequestOptions = new() { BypassIntegratedCache = true },
            CosmosThresholdOptions = new() { NonPointOperationLatencyThreshold = TimeSpan.FromSeconds(9) }
        };

        QueryRequestOptions snapshot = ContentValidationRequestOptions.Snapshot(options, stream: false)!;
        regions.Add(Regions.WestUS);
        options.DedicatedGatewayRequestOptions.BypassIntegratedCache = false;
        options.CosmosThresholdOptions.NonPointOperationLatencyThreshold = TimeSpan.FromMinutes(1);

        Assert.Equal(7, snapshot.MaxItemCount);
        Assert.Equal(3, snapshot.MaxConcurrency);
        Assert.Equal("session", snapshot.SessionToken);
        Assert.False(snapshot.PopulateIndexMetrics);
        Assert.False(snapshot.PopulateQueryAdvice);
        Assert.Single(snapshot.ExcludeRegions);
        Assert.True(snapshot.DedicatedGatewayRequestOptions.BypassIntegratedCache);
        Assert.Equal(TimeSpan.FromSeconds(9), snapshot.CosmosThresholdOptions.NonPointOperationLatencyThreshold);
        QueryRequestOptions streamSnapshot = ContentValidationRequestOptions.Snapshot(options, stream: true)!;
        Assert.False(streamSnapshot.PopulateIndexMetrics);
        Assert.False(streamSnapshot.PopulateQueryAdvice);
        QueryRequestOptions explicitFalse = ContentValidationRequestOptions.Snapshot(
            new QueryRequestOptions { PopulateIndexMetrics = false, PopulateQueryAdvice = false }, stream: true)!;
        Assert.False(explicitFalse.PopulateIndexMetrics);
        Assert.False(explicitFalse.PopulateQueryAdvice);
        Assert.Throws<NotSupportedException>(() => ContentValidationRequestOptions.Snapshot(
            new QueryRequestOptions { PopulateIndexMetrics = true }, stream: false));
        Assert.Throws<NotSupportedException>(() => ContentValidationRequestOptions.Snapshot(
            new QueryRequestOptions { PopulateQueryAdvice = true }, stream: true));
        Assert.Throws<NotSupportedException>(() => ContentValidationRequestOptions.Snapshot(new QueryRequestOptions { QueryTextMode = QueryTextMode.All }, false));
        Assert.Throws<NotSupportedException>(() => ContentValidationRequestOptions.Snapshot(new DerivedQueryOptions(), false));
    }

    [Fact]
    public void ChangeFeedOptionsUseBaseEtagsAndSnapshotMutableValues()
    {
        List<string> regions = [Regions.NorthEurope];
        ChangeFeedRequestOptions options = new()
        {
            PageSizeHint = 13,
            PriorityLevel = PriorityLevel.Low,
            ThroughputBucket = 5,
            ExcludeRegions = regions,
            CosmosThresholdOptions = new() { RequestChargeThreshold = 8 }
        };
        ChangeFeedRequestOptions snapshot = ContentValidationRequestOptions.Snapshot(options)!;
        regions.Add(Regions.WestEurope);
        options.CosmosThresholdOptions.RequestChargeThreshold = 99;
        Assert.Equal(13, snapshot.PageSizeHint);
        Assert.Single(snapshot.ExcludeRegions);
        Assert.Equal(8, snapshot.CosmosThresholdOptions.RequestChargeThreshold);

        ((RequestOptions)options).IfNoneMatchEtag = "unsafe";
        Assert.Throws<NotSupportedException>(() => ContentValidationRequestOptions.Snapshot(options));
    }

    [Fact]
    public void UnsafeHooksAndDerivedNestedOptionsAreRejected()
    {
        QueryRequestOptions[] invalid =
        [
            new() { Properties = new Dictionary<string, object>() },
            new() { AddRequestHeaders = _ => throw new InvalidOperationException() },
            new() { IfMatchEtag = "etag" },
            new() { DedicatedGatewayRequestOptions = new DerivedGatewayOptions() },
            new() { CosmosThresholdOptions = new DerivedThresholdOptions() }
        ];
        foreach (QueryRequestOptions options in invalid)
            Assert.Throws<NotSupportedException>(() => ContentValidationRequestOptions.Snapshot(options, false));
    }

    private static async Task<byte[]> ReadAll(Stream stream)
    {
        using MemoryStream destination = new();
        await stream.CopyToAsync(destination);
        return destination.ToArray();
    }

    private static TrackingResponse Response(HttpStatusCode status, Stream? content = null) => new(status) { Content = content! };

    public sealed class TypedItem
    {
        public string Id { get; set; } = "";
        public int Value { get; set; }
    }

    public sealed class ConstructionProbe
    {
        public static int Constructions;
        public ConstructionProbe() => Interlocked.Increment(ref Constructions);
        public string Id { get; set; } = "";
    }

    public sealed class CancellingProbe
    {
        public static CancellationTokenSource? Cancellation;
        public CancellingProbe() => Cancellation?.Cancel();
        public string Id { get; set; } = "";
    }

    private sealed class Harness : IDisposable
    {
        private readonly UnsafeEcdsaContentSigner signer;
        private readonly UnsafeEcdsaContentVerifier verifier;
        public CountingVerifier Verifier { get; }
        public ContentValidationProcessor Processor { get; }
        public CosmosClient? Client { get; }

        public Harness(ContentValidationOptions? options = null, bool createClient = false)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            signer = new UnsafeEcdsaContentSigner("feed-test", key.ExportPkcs8PrivateKeyPem());
            verifier = new UnsafeEcdsaContentVerifier("feed-test", key.ExportSubjectPublicKeyInfoPem());
            Verifier = new CountingVerifier(verifier);
            Processor = UnsafeSampleProviders.CreateProcessor(options ?? new(), new UnsafeInMemoryVerificationKeyResolver([Verifier]), signer);
            if (createClient)
                Client = new CosmosClient(Endpoint, Key, new CosmosClientOptions { Serializer = new ContentValidationSerializer(Processor) });
        }

        public string Sign(string id, int value)
        {
            using RecyclableMemoryStream signed = Processor.Sign(new(Encoding.UTF8.GetBytes($"{{\"id\":\"{id}\",\"pk\":\"p\",\"value\":{value}}}")));
            return Encoding.UTF8.GetString(signed.GetReadOnlySequence().ToArray());
        }

        public byte[] Page(params string[] documents) => Encoding.UTF8.GetBytes(
            "{\"Documents\":[" + string.Join(',', documents) + "],\"_count\":" + documents.Length + ",\"metadata\":{\"kept\":true}}");

        public void Dispose()
        {
            Client?.Dispose();
            signer.Dispose();
            verifier.Dispose();
        }
    }

    private sealed class FakeIterator : FeedIterator
    {
        private readonly Queue<ResponseMessage> responses;
        public int ReadCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public Action? AfterRead { get; init; }

        public FakeIterator(params ResponseMessage[] responses) => this.responses = new(responses);
        public override bool HasMoreResults => responses.Count != 0;
        public override Task<ResponseMessage> ReadNextAsync(CancellationToken cancellationToken = default)
        {
            ReadCalls++;
            cancellationToken.ThrowIfCancellationRequested();
            ResponseMessage response = responses.Dequeue();
            AfterRead?.Invoke();
            return Task.FromResult(response);
        }
        protected override void Dispose(bool disposing)
        {
            if (!disposing) return;
            DisposeCalls++;
            while (responses.TryDequeue(out ResponseMessage? response)) response.Dispose();
        }
    }

    private sealed class ThrowOnceIterator(ResponseMessage response) : FeedIterator
    {
        private bool thrown;
        private bool returned;
        public int DisposeCalls { get; private set; }
        public override bool HasMoreResults => !returned;
        public override Task<ResponseMessage> ReadNextAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!thrown)
            {
                thrown = true;
                throw new IOException("transient transport failure");
            }
            returned = true;
            return Task.FromResult(response);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeCalls++;
        }
    }

    private sealed class TrackingResponse(HttpStatusCode statusCode) : ResponseMessage(statusCode)
    {
        public int DisposeCalls { get; private set; }
        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeCalls++;
            base.Dispose(disposing);
        }
    }

    private sealed class LazyContentResponse(TrackingStream body) : ResponseMessage(HttpStatusCode.OK)
    {
        public int DisposeCalls { get; private set; }
        public override Stream Content => body;
        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeCalls++;
            base.Dispose(disposing);
        }
    }

    private sealed class TrackingStream(byte[] bytes, bool seekable = true) : MemoryStream(bytes)
    {
        public int ReadCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public Action? BeforeFirstRead { get; init; }
        public override bool CanSeek => seekable && base.CanSeek;
        public override byte[] ToArray() => throw new InvalidOperationException("Feed bodies must not be flattened.");
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ReadCalls++;
            if (ReadCalls == 1) BeforeFirstRead?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            return await base.ReadAsync(buffer[..Math.Min(buffer.Length, 113)], cancellationToken);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeCalls++;
            base.Dispose(disposing);
        }
    }

    private sealed class DerivedQueryOptions : QueryRequestOptions;
    private sealed class DerivedGatewayOptions : DedicatedGatewayRequestOptions;
    private sealed class DerivedThresholdOptions : CosmosThresholdOptions;

    public sealed class CountingVerifier(IContentVerifier inner) : IContentVerifier
    {
        public int VerifyCalls { get; private set; }
        public string KeyId => inner.KeyId;
        public string AlgorithmId => inner.AlgorithmId;
        public bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
        {
            VerifyCalls++;
            return inner.VerifyHash(hash, signature);
        }
    }

    private sealed class MismatchedResolver : IVerificationKeyResolver
    {
        public IContentVerifier Resolve(string keyId) => new MismatchedVerifier();
    }

    private sealed class MismatchedVerifier : IContentVerifier
    {
        public string KeyId => "different-key";
        public string AlgorithmId => "ECDSA-P256-SHA256-P1363";
        public bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature) => throw new InvalidOperationException("Must not verify.");
    }
}
