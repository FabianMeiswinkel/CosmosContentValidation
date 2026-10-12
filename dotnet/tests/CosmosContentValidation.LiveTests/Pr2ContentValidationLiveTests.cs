using System.Net;
using System.Text.Json;
using Microsoft.Azure.Cosmos;
using Xunit;
using Xunit.Abstractions;

namespace CosmosContentValidation.LiveTests;

/// <summary>PR2 lifecycle, full-document query, continuation and latest-version pull-feed coverage.</summary>
[Collection("Cosmos content validation live")]
public sealed class Pr2ContentValidationLiveTests(LiveSigningFixture fixture, ITestOutputHelper output)
    : IClassFixture<LiveSigningFixture>
{
    [LiveTheory]
    [InlineData(ConnectionMode.Direct)]
    [InlineData(ConnectionMode.Gateway)]
    public Task ReplaceAndUpsertLifecycleWithContentOnAndOff(ConnectionMode mode) => RunAsync(mode, async scope =>
    {
        LiveItem typed = scope.NewItem("typed");
        LiveDocument typedModel = NewDocument(typed, 7);
        ItemResponse<LiveDocument> created = await scope.CreateTypedAsync(typed, typedModel);
        LiveCheck.Status(created.StatusCode, HttpStatusCode.Created);
        CheckDocument(created.Resource, typed, 7);

        typedModel.Value = 8;
        string staleEtag = typed.ETag!;
        ItemResponse<LiveDocument> replaced = await scope.Writer.ReplaceItemAsync(typedModel, typed.Id, typed.PartitionKey,
            new ItemRequestOptions { IfMatchEtag = typed.ETag, EnableContentResponseOnWrite = true }, scope.Token);
        Observe(typed, replaced.Headers);
        LiveCheck.Status(replaced.StatusCode, HttpStatusCode.OK);
        CheckDocument(replaced.Resource, typed, 8);

        CosmosException stale = await Assert.ThrowsAsync<CosmosException>(() => scope.Writer.ReplaceItemAsync(
            typedModel, typed.Id, typed.PartitionKey,
            new ItemRequestOptions { IfMatchEtag = staleEtag, EnableContentResponseOnWrite = false }, scope.Token));
        LiveCheck.Status(stale.StatusCode, HttpStatusCode.PreconditionFailed);

        typedModel.Value = 9;
        ItemResponse<LiveDocument> statusOnly = await scope.UpsertTypedAsync(typed, typedModel, enableContentResponse: false);
        LiveCheck.Status(statusOnly.StatusCode, HttpStatusCode.OK);
        ItemResponse<LiveDocument> typedRead = await scope.Reader.ReadItemAsync<LiveDocument>(
            typed.Id, typed.PartitionKey, typed.ReadOptions(), scope.Token);
        CheckDocument(typedRead.Resource, typed, 9);

        LiveItem streamed = scope.NewItem("stream");
        using (MemoryStream insert = Payload(NewDocument(streamed, 7)))
        using (ResponseMessage response = await scope.UpsertStreamAsync(streamed, insert))
        {
            LiveCheck.Status(response.StatusCode, HttpStatusCode.Created);
            LiveCheck.Require(insert.Position == 0, "Stream upsert insert changed caller position.");
            await CheckEnvelopeAsync(response, streamed, 7, scope.Token);
        }

        using (MemoryStream update = Payload(NewDocument(streamed, 8)))
        using (ResponseMessage response = await scope.Writer.ReplaceItemStreamAsync(update, streamed.Id, streamed.PartitionKey,
            new ItemRequestOptions { IfMatchEtag = streamed.ETag, EnableContentResponseOnWrite = false }, scope.Token))
        {
            response.EnsureSuccessStatusCode();
            LiveCheck.Status(response.StatusCode, HttpStatusCode.OK);
            Observe(streamed, response.Headers);
            LiveCheck.Require(update.Position == 0, "Stream replace changed caller position.");
        }
        ItemResponse<LiveDocument> streamReadback = await scope.Reader.ReadItemAsync<LiveDocument>(
            streamed.Id, streamed.PartitionKey, streamed.ReadOptions(), scope.Token);
        CheckDocument(streamReadback.Resource, streamed, 8);
    });

    [LiveTheory]
    [InlineData(ConnectionMode.Direct)]
    [InlineData(ConnectionMode.Gateway)]
    public Task FullDocumentQueriesValidateParametersPagesAndResume(ConnectionMode mode) => RunAsync(mode, async scope =>
    {
        LiveItem first = scope.NewItem("a");
        LiveItem second = scope.NewItem("b");
        await scope.CreateTypedAsync(first, NewDocument(first, 1));
        await scope.CreateTypedAsync(second, NewDocument(second, 2));

        // Prime the public-only client's session cache for both logical partitions.
        _ = (await scope.Reader.ReadItemAsync<LiveDocument>(first.Id, first.PartitionKey, first.ReadOptions(), scope.Token)).Resource;
        _ = (await scope.Reader.ReadItemAsync<LiveDocument>(second.Id, second.PartitionKey, second.ReadOptions(), scope.Token)).Resource;

        ContentValidationQueryDefinition single = new ContentValidationQueryDefinition(
            "SELECT * FROM c WHERE c.pk = @pk AND c.id = @identity.id")
            .WithParameter("@pk", first.Pk)
            .WithParameter("@identity", new { id = first.Id });
        using (FeedIterator<LiveDocument> iterator = scope.Reader.GetItemQueryIterator<LiveDocument>(single,
            requestOptions: new QueryRequestOptions { PartitionKey = first.PartitionKey, MaxItemCount = 1 }))
        {
            FeedResponse<LiveDocument> page = await iterator.ReadNextAsync(scope.Token);
            CheckDocument(page.Single(), first, 1);
        }

        string[] ids = [first.Id, second.Id];
        ContentValidationQueryDefinition cross = new ContentValidationQueryDefinition(
            "SELECT * FROM c WHERE ARRAY_CONTAINS(@ids, c.id) ORDER BY c.id")
            .WithParameter("@ids", ids);
        HashSet<string> observed = new(StringComparer.Ordinal);
        string? continuation;
        using (FeedIterator<LiveDocument> initial = scope.Reader.GetItemQueryIterator<LiveDocument>(cross,
            requestOptions: new QueryRequestOptions { MaxItemCount = 1 }))
        {
            FeedResponse<LiveDocument> page = await initial.ReadNextAsync(scope.Token);
            foreach (LiveDocument document in page) observed.Add(document.Id);
            continuation = page.ContinuationToken;
        }
        LiveCheck.Require(!string.IsNullOrWhiteSpace(continuation), "Expected a continuation after the first one-item query page.");
        using (FeedIterator<LiveDocument> resumed = scope.Reader.GetItemQueryIterator<LiveDocument>(cross, continuation,
            new QueryRequestOptions { MaxItemCount = 1 }))
        {
            while (resumed.HasMoreResults)
            {
                FeedResponse<LiveDocument> page = await resumed.ReadNextAsync(scope.Token);
                foreach (LiveDocument document in page) observed.Add(document.Id);
            }
        }
        LiveCheck.Require(observed.SetEquals(ids), "Continuation resume did not materialize both signed documents.");

        using FeedIterator stream = scope.Reader.GetItemQueryStreamIterator(cross,
            requestOptions: new QueryRequestOptions { MaxItemCount = 1 });
        using ResponseMessage streamPage = await stream.ReadNextAsync(scope.Token);
        streamPage.EnsureSuccessStatusCode();
        using JsonDocument envelope = await JsonDocument.ParseAsync(streamPage.Content, cancellationToken: scope.Token);
        LiveCheck.Require(envelope.RootElement.TryGetProperty("Documents", out JsonElement documents)
            && documents.ValueKind == JsonValueKind.Array && documents.GetArrayLength() == 1,
            "Stream query did not preserve the validated Documents envelope.");
    });

    [LiveTheory]
    [InlineData(ConnectionMode.Direct)]
    [InlineData(ConnectionMode.Gateway)]
    public Task LatestVersionTypedAndStreamPullFeedUsesValidatedCheckpoints(ConnectionMode mode) => RunAsync(mode, async scope =>
    {
        LiveItem item = scope.NewItem("feed");
        string typedCheckpoint = await TypedNowAsync(scope, item);
        string streamCheckpoint = await StreamNowAsync(scope, item);
        ItemResponse<LiveDocument> inserted = await scope.UpsertTypedAsync(item, NewDocument(item, 7));
        LiveCheck.Status(inserted.StatusCode, HttpStatusCode.Created);

        await PollTypedAsync(scope, typedCheckpoint, item);
        await PollStreamAsync(scope, streamCheckpoint, item);
    });

    private Task RunAsync(ConnectionMode mode, Func<LiveTestScope, Task> test) =>
        LiveTestScope.RunAsync(fixture, output, mode, customPolicy: false, test);

    private static LiveDocument NewDocument(LiveItem item, int value) => new()
    {
        Id = item.Id,
        Pk = item.Pk,
        Value = value,
        Ttl = -1,
        CustomerTag = "initial",
        Nested = new LiveNestedDocument { CustomerTag = "nested-original", Ttl = -1 }
    };

    private static MemoryStream Payload(LiveDocument document) =>
        new(JsonSerializer.SerializeToUtf8Bytes(document), writable: false);

    private static void Observe(LiveItem item, Headers headers)
    {
        item.SessionToken = headers["x-ms-session-token"];
        item.ETag = headers.ETag;
    }

    private static void CheckDocument(LiveDocument document, LiveItem item, int value) => LiveCheck.Require(
        document is not null && document.Id == item.Id && document.Pk == item.Pk && document.Value == value,
        "Materialized document did not match the test-owned identity/value.");

    private static async Task CheckEnvelopeAsync(ResponseMessage response, LiveItem item, int value, CancellationToken token)
    {
        response.EnsureSuccessStatusCode();
        using JsonDocument json = await JsonDocument.ParseAsync(response.Content, cancellationToken: token);
        JsonElement root = json.RootElement;
        LiveCheck.Require(root.GetProperty("id").GetString() == item.Id && root.GetProperty("value").GetInt32() == value
            && root.TryGetProperty(ContentValidationProcessor.SignaturePropertyName, out _),
            "Stream write response did not retain the validated signed document.");
        response.Content.Position = 0;
    }

    private static async Task<string> TypedNowAsync(LiveTestScope scope, LiveItem item)
    {
        using FeedIterator<LiveDocument> iterator = scope.Reader.GetChangeFeedIterator<LiveDocument>(
            ChangeFeedStartFrom.Now(FeedRange.FromPartitionKey(item.PartitionKey)), ChangeFeedMode.LatestVersion,
            new ChangeFeedRequestOptions { PageSizeHint = 1 });
        FeedResponse<LiveDocument> page = await iterator.ReadNextAsync(scope.Token);
        LiveCheck.Require(page.Count == 0 && !string.IsNullOrWhiteSpace(page.ContinuationToken),
            "Typed NOW checkpoint was not an empty page with continuation.");
        return page.ContinuationToken;
    }

    private static async Task<string> StreamNowAsync(LiveTestScope scope, LiveItem item)
    {
        using FeedIterator iterator = scope.Reader.GetChangeFeedStreamIterator(
            ChangeFeedStartFrom.Now(FeedRange.FromPartitionKey(item.PartitionKey)), ChangeFeedMode.LatestVersion,
            new ChangeFeedRequestOptions { PageSizeHint = 1 });
        using ResponseMessage page = await iterator.ReadNextAsync(scope.Token);
        LiveCheck.Status(page.StatusCode, HttpStatusCode.NotModified);
        LiveCheck.Require(!string.IsNullOrWhiteSpace(page.ContinuationToken), "Stream NOW checkpoint omitted continuation.");
        return page.ContinuationToken;
    }

    private static async Task PollTypedAsync(LiveTestScope scope, string checkpoint, LiveItem item)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        string continuation = checkpoint;
        while (DateTime.UtcNow < deadline)
        {
            using FeedIterator<LiveDocument> iterator = scope.Reader.GetChangeFeedIterator<LiveDocument>(
                ChangeFeedStartFrom.ContinuationToken(continuation), ChangeFeedMode.LatestVersion,
                new ChangeFeedRequestOptions { PageSizeHint = 1 });
            FeedResponse<LiveDocument> page = await iterator.ReadNextAsync(scope.Token);
            if (page.Any(document => document.Id == item.Id)) return;
            LiveCheck.Require(!string.IsNullOrWhiteSpace(page.ContinuationToken), "Typed feed page omitted continuation.");
            continuation = page.ContinuationToken;
            if (page.Count == 0) await Task.Delay(250, scope.Token);
        }
        throw new LiveTestFailure("Typed latest-version feed did not observe the owned item within 30 seconds.");
    }

    private static async Task PollStreamAsync(LiveTestScope scope, string checkpoint, LiveItem item)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        string continuation = checkpoint;
        while (DateTime.UtcNow < deadline)
        {
            using FeedIterator iterator = scope.Reader.GetChangeFeedStreamIterator(
                ChangeFeedStartFrom.ContinuationToken(continuation), ChangeFeedMode.Incremental,
                new ChangeFeedRequestOptions { PageSizeHint = 1 });
            using ResponseMessage page = await iterator.ReadNextAsync(scope.Token);
            if (page.StatusCode == HttpStatusCode.NotModified)
            {
                LiveCheck.Require(!string.IsNullOrWhiteSpace(page.ContinuationToken), "Stream 304 feed page omitted continuation.");
                continuation = page.ContinuationToken;
                await Task.Delay(250, scope.Token);
                continue;
            }
            page.EnsureSuccessStatusCode();
            using JsonDocument envelope = await JsonDocument.ParseAsync(page.Content, cancellationToken: scope.Token);
            bool found = envelope.RootElement.GetProperty("Documents").EnumerateArray()
                .Any(document => document.GetProperty("id").GetString() == item.Id);
            if (found) return;
            LiveCheck.Require(!string.IsNullOrWhiteSpace(page.ContinuationToken), "Stream feed page omitted continuation.");
            continuation = page.ContinuationToken;
        }
        throw new LiveTestFailure("Stream latest-version feed did not observe the owned item within 30 seconds.");
    }
}
