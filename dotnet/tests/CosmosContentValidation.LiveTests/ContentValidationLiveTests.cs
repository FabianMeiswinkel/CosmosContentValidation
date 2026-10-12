using System.Buffers;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Azure.Cosmos;
using Xunit;
using Xunit.Abstractions;

namespace CosmosContentValidation.LiveTests;

/// <summary>
/// PR1 point create/read only. Raw patches are deliberate test-local tampering, not supported
/// protected operations. All documents explicitly disable expiry initially (ttl=-1).
/// Six theories / 24 rows; each scenario runs against Direct and Gateway independently.
/// </summary>
[Collection("Cosmos content validation live")]
public sealed class ContentValidationLiveTests(LiveSigningFixture fixture, ITestOutputHelper output)
    : IClassFixture<LiveSigningFixture>
{
    [LiveTheory]
    [InlineData(ConnectionMode.Direct)]
    [InlineData(ConnectionMode.Gateway)]
    public Task TypedCreateAndPublicOnlyReadsRoundTrip(ConnectionMode mode) => RunAsync(mode, false, async scope =>
    {
        LiveItem item = scope.NewItem();
        await CreateAndCheckAsync(scope, item, streamCreate: false);
        await ReadBothAsync(scope, item);
    });

    [LiveTheory]
    [InlineData(ConnectionMode.Direct)]
    [InlineData(ConnectionMode.Gateway)]
    public Task StreamCreateAndPublicOnlyReadsRoundTrip(ConnectionMode mode) => RunAsync(mode, false, async scope =>
    {
        LiveItem item = scope.NewItem();
        await CreateAndCheckAsync(scope, item, streamCreate: true);
        await ReadBothAsync(scope, item);
    });

    [LiveTheory]
    [InlineData(ConnectionMode.Direct, "/value")]
    [InlineData(ConnectionMode.Gateway, "/value")]
    [InlineData(ConnectionMode.Direct, "/ttl")]
    [InlineData(ConnectionMode.Gateway, "/ttl")]
    [InlineData(ConnectionMode.Direct, "/customerTag")]
    [InlineData(ConnectionMode.Gateway, "/customerTag")]
    public Task DefaultPolicyRejectsRawApplicationAndRootChanges(ConnectionMode mode, string path) => RunAsync(mode, false, async scope =>
    {
        LiveItem item = scope.NewItem();
        await CreateAndCheckAsync(scope, item, streamCreate: path == "/customerTag");
        await ReadBothAsync(scope, item); // Establish successful public-only reads before tampering.
        PatchOperation change = path switch
        {
            "/value" => PatchOperation.Set(path, 8),
            "/ttl" => PatchOperation.Set(path, 86400), // Long-lived even if the container enables TTL.
            "/customerTag" => PatchOperation.Set(path, "changed"),
            _ => throw new LiveTestFailure("Unexpected test-owned patch path.")
        };
        await scope.TamperAsync(item, change);
        await RejectBothReadsAsync(scope, item);
    });

    [LiveTheory]
    [InlineData(ConnectionMode.Direct, false)]
    [InlineData(ConnectionMode.Gateway, false)]
    [InlineData(ConnectionMode.Direct, true)]
    [InlineData(ConnectionMode.Gateway, true)]
    public Task CustomPolicyAllowsExactRootAddRemoveAndChange(ConnectionMode mode, bool streamCreate) => RunAsync(mode, true, async scope =>
    {
        LiveItem item = scope.NewItem();
        await CreateAndCheckAsync(scope, item, streamCreate);
        await ReadBothAsync(scope, item);

        await scope.TamperAsync(item, PatchOperation.Set("/ttl", -1), PatchOperation.Set("/customerTag", "changed"));
        await ReadBothAsync(scope, item, expectedTag: "changed");

        await scope.TamperAsync(item, PatchOperation.Remove("/customerTag"));
        await ReadBothAsync(scope, item, expectedTag: null);

        await scope.TamperAsync(item, PatchOperation.Add("/customerTag", "added"), PatchOperation.Set("/ttl", 86400));
        await ReadBothAsync(scope, item, expectedTtl: 86400, expectedTag: "added");
        // Root exclusions permit changes without a signer. Nested same-name fields were unchanged.
    });

    [LiveTheory]
    [InlineData(ConnectionMode.Direct, "/nested/customerTag")]
    [InlineData(ConnectionMode.Gateway, "/nested/customerTag")]
    [InlineData(ConnectionMode.Direct, "/nested/ttl")]
    [InlineData(ConnectionMode.Gateway, "/nested/ttl")]
    [InlineData(ConnectionMode.Direct, "/CustomerTag")]
    [InlineData(ConnectionMode.Gateway, "/CustomerTag")]
    [InlineData(ConnectionMode.Direct, "/TTL")]
    [InlineData(ConnectionMode.Gateway, "/TTL")]
    public Task CustomPolicyStillSignsNestedAndCaseVariantNames(ConnectionMode mode, string path) => RunAsync(mode, true, async scope =>
    {
        LiveItem item = scope.NewItem();
        await CreateAndCheckAsync(scope, item, streamCreate: true);
        await ReadBothAsync(scope, item);
        PatchOperation change = path is "/nested/ttl" or "/TTL"
            ? PatchOperation.Set(path, 86400)
            : PatchOperation.Set(path, "changed");
        await scope.TamperAsync(item, change);
        await RejectBothReadsAsync(scope, item);
    });

    [LiveTheory]
    [InlineData(ConnectionMode.Direct)]
    [InlineData(ConnectionMode.Gateway)]
    public Task PublicOnlyTypedAndStreamWritesRejectSigningUnavailable(ConnectionMode mode) => RunAsync(mode, false, async scope =>
    {
        LiveItem typedItem = scope.NewItem();
        await ExpectValidationAsync(ContentValidationFailure.SigningUnavailable, async () =>
        {
            // Do not use Assert.Throws around an unowned response. Even an unexpected success is
            // registered before materialization, and therefore eligible for scoped cleanup.
            ItemResponse<LiveDocument> response = await scope.CreateTypedAsync(typedItem, NewDocument(typedItem), publicOnly: true);
            _ = response.Resource;
        });

        LiveItem streamItem = scope.NewItem();
        using MemoryStream payload = CallerPayload(NewDocument(streamItem));
        long originalPosition = payload.Position;
        await ExpectValidationAsync(ContentValidationFailure.SigningUnavailable, async () =>
        {
            using ResponseMessage response = await scope.CreateStreamAsync(streamItem, payload, publicOnly: true);
            // If the guard regresses, this using owns the successful OR error response and body.
        });
        await CheckCallerPayloadAsync(payload, originalPosition, streamItem, scope.Token);
    });

    private Task RunAsync(ConnectionMode mode, bool customPolicy, Func<LiveTestScope, Task> test) =>
        LiveTestScope.RunAsync(fixture, output, mode, customPolicy, test);

    private static LiveDocument NewDocument(LiveItem item) => new()
    {
        Id = item.Id,
        Pk = item.Pk,
        Value = 7,
        Ttl = -1,
        CustomerTag = "initial",
        Nested = new LiveNestedDocument { CustomerTag = "nested-original", Ttl = -1 }
    };

    private static async Task CreateAndCheckAsync(LiveTestScope scope, LiveItem item, bool streamCreate)
    {
        LiveDocument callerDocument = NewDocument(item);
        if (streamCreate)
        {
            using MemoryStream payload = CallerPayload(callerDocument);
            long originalPosition = payload.Position;
            using ResponseMessage response = await scope.CreateStreamAsync(item, payload);
            LiveCheck.Status(response.StatusCode, HttpStatusCode.Created);
            LiveCheck.ItemHeaders(response.Headers);
            await CheckCallerPayloadAsync(payload, originalPosition, item, scope.Token);
            await CheckStreamResponseAsync(scope, response, item);
            // Both payload and response body remain alive throughout all caller consumption above.
        }
        else
        {
            ItemResponse<LiveDocument> response = await scope.CreateTypedAsync(item, callerDocument);
            LiveCheck.Status(response.StatusCode, HttpStatusCode.Created);
            LiveCheck.ItemHeaders(response.Headers);
            CheckTypedResponse(response, item);
        }
        LiveCheck.Require(callerDocument.Rid is null && callerDocument.Self is null && callerDocument.ETag is null
            && callerDocument.Attachments is null && callerDocument.Timestamp is null && callerDocument.Extra is null,
            "Protected create mutated the caller's model with service/signature metadata.");
        LiveCheck.Require(callerDocument.Value == 7 && callerDocument.Ttl == -1 && callerDocument.CustomerTag == "initial",
            "Protected create mutated the caller's application fields.");
    }

    private static async Task ReadBothAsync(LiveTestScope scope, LiveItem item, int expectedTtl = -1, string? expectedTag = "initial")
    {
        ItemResponse<LiveDocument> typed = await scope.Reader.ReadItemAsync<LiveDocument>(
            item.Id, item.PartitionKey, item.ReadOptions(), scope.Token);
        LiveCheck.Status(typed.StatusCode, HttpStatusCode.OK);
        LiveCheck.ItemHeaders(typed.Headers);
        CheckTypedResponse(typed, item, expectedTtl, expectedTag);

        using ResponseMessage streamed = await scope.Reader.ReadItemStreamAsync(
            item.Id, item.PartitionKey, item.ReadOptions(), scope.Token);
        LiveCheck.Status(streamed.StatusCode, HttpStatusCode.OK);
        LiveCheck.ItemHeaders(streamed.Headers);
        await CheckStreamResponseAsync(scope, streamed, item, expectedTtl, expectedTag);
    }

    private static void CheckTypedResponse(ItemResponse<LiveDocument> response, LiveItem item, int expectedTtl = -1, string? expectedTag = "initial")
    {
        // Status-only assertions would miss serializer/lazy materialization failures.
        LiveDocument document = response.Resource;
        CheckDocument(document, item, response.Headers.ETag, expectedTtl, expectedTag);
        LiveCheck.Require(document.Extra is null || !document.Extra.ContainsKey(ContentValidationProcessor.SignaturePropertyName),
            "Typed mapping must strip the validated envelope before returning the model.");
    }

    private static async Task CheckStreamResponseAsync(LiveTestScope scope, ResponseMessage response, LiveItem item,
        int expectedTtl = -1, string? expectedTag = "initial")
    {
        Stream? stream = response.Content;
        LiveCheck.Require(stream is not null && stream.CanRead && stream.CanSeek, "Protected response body must remain readable and seekable.");
        Stream content = stream!; // Borrowed: response, not this helper, owns the stream.
        LiveCheck.Require(content.Position == 0, "Protected response body must be rewound to position zero.");
        LiveCheck.Require(content.Length > 0 && content.Length <= 64 * 1024, "Protected response body has an unexpected size.");
        byte[] first = new byte[checked((int)content.Length)];
        await content.ReadExactlyAsync(first.AsMemory(), scope.Token);
        LiveCheck.Require(content.ReadByte() == -1, "First response read did not consume the complete body.");
        content.Position = 0;
        byte[] replay = new byte[first.Length];
        await content.ReadExactlyAsync(replay.AsMemory(), scope.Token);
        LiveCheck.Require(content.ReadByte() == -1 && first.AsSpan().SequenceEqual(replay), "Rewound response did not replay identical content.");
        content.Position = 0;

        // Revalidate actual returned bytes with the independent public-only processor, including
        // the five service fields; do not validate a reserialized approximation of the POCO.
        scope.ReaderProcessor.Validate(new ReadOnlySequence<byte>(first));
        using JsonDocument json = JsonDocument.Parse(first);
        JsonElement root = json.RootElement;
        LiveCheck.Require(root.TryGetProperty(ContentValidationProcessor.SignaturePropertyName, out JsonElement envelope)
            && envelope.ValueKind == JsonValueKind.Object, "Stream response must retain its signed envelope.");
        LiveCheck.Require(root.TryGetProperty("ttl", out JsonElement ttl) && ttl.GetInt32() == expectedTtl,
            "Stream response did not preserve the exact root ttl field.");
        bool hasTag = root.TryGetProperty("customerTag", out JsonElement tag);
        LiveCheck.Require(expectedTag is null ? !hasTag : hasTag && tag.GetString() == expectedTag,
            "Stream response did not preserve root customerTag addition/removal/change.");
        LiveDocument? document = root.Deserialize<LiveDocument>();
        CheckDocument(document, item, response.Headers.ETag, expectedTtl, expectedTag);
        LiveCheck.Require(content.CanRead && content.CanSeek && content.Position == 0,
            "Caller consumption must leave the response body alive and replayable until response disposal.");
    }

    private static void CheckDocument(LiveDocument? document, LiveItem item, string headerETag, int expectedTtl, string? expectedTag)
    {
        LiveCheck.Require(document is not null, "The actual response Resource did not materialize.");
        LiveDocument value = document!;
        LiveCheck.Require(value.Id == item.Id && value.Pk == item.Pk, "Returned identity does not match this test's generated item.");
        LiveCheck.Require(value.Value == 7 && value.Ttl == expectedTtl && value.CustomerTag == expectedTag,
            "Returned application/ignored fields differ from the expected test values.");
        LiveCheck.Require(value.Nested is { CustomerTag: "nested-original", Ttl: -1 }, "Nested signed fields were not preserved.");
        LiveCheck.Require(!string.IsNullOrWhiteSpace(value.Rid), "Service _rid did not materialize.");
        LiveCheck.Require(!string.IsNullOrWhiteSpace(value.Self), "Service _self did not materialize.");
        LiveCheck.Require(!string.IsNullOrWhiteSpace(value.ETag) && value.ETag == headerETag, "Service _etag did not materialize or match its response header.");
        LiveCheck.Require(!string.IsNullOrWhiteSpace(value.Attachments), "Service _attachments did not materialize.");
        LiveCheck.Require(value.Timestamp is > 0, "Service _ts did not materialize.");
    }

    private static async Task RejectBothReadsAsync(LiveTestScope scope, LiveItem item)
    {
        await ExpectValidationAsync(ContentValidationFailure.InvalidSignature, async () =>
        {
            ItemResponse<LiveDocument> response = await scope.Reader.ReadItemAsync<LiveDocument>(
                item.Id, item.PartitionKey, item.ReadOptions(), scope.Token);
            _ = response.Resource;
        });
        await ExpectValidationAsync(ContentValidationFailure.InvalidSignature, async () =>
        {
            using ResponseMessage response = await scope.Reader.ReadItemStreamAsync(
                item.Id, item.PartitionKey, item.ReadOptions(), scope.Token);
        });
    }

    private static async Task ExpectValidationAsync(ContentValidationFailure expected, Func<Task> operation)
    {
        bool rejected = false;
        try { await operation(); }
        catch (ContentValidationException exception)
        {
            LiveCheck.Require(exception.Failure == expected,
                $"Wrong validation reason: expected={expected}, actual={exception.Failure}.");
            rejected = true;
        }
        LiveCheck.Require(rejected, $"Operation did not reject with {expected}.");
    }

    private static MemoryStream CallerPayload(LiveDocument document)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(document);
        const int offset = 11;
        byte[] bytes = new byte[offset + json.Length];
        bytes.AsSpan(0, offset).Fill((byte)'x'); // Not valid JSON: reading from zero would fail.
        json.CopyTo(bytes.AsSpan(offset));
        return new MemoryStream(bytes, writable: false) { Position = offset };
    }

    private static async Task CheckCallerPayloadAsync(Stream payload, long originalPosition, LiveItem item, CancellationToken token)
    {
        LiveCheck.Require(payload.CanRead && payload.CanSeek && payload.Position == originalPosition,
            "Create must leave caller input open and restore its original, nonzero position.");
        using JsonDocument json = await JsonDocument.ParseAsync(payload, cancellationToken: token);
        JsonElement root = json.RootElement;
        LiveCheck.Require(root.GetProperty("id").GetString() == item.Id && root.GetProperty("pk").GetString() == item.Pk
            && root.GetProperty("value").GetInt32() == 7 && root.GetProperty("ttl").GetInt32() == -1
            && root.GetProperty("customerTag").GetString() == "initial"
            && !root.TryGetProperty(ContentValidationProcessor.SignaturePropertyName, out _),
            "Create changed the caller's unsigned payload.");
        payload.Position = originalPosition; // Caller can independently rewind/replay its input too.
    }
}

internal sealed class LiveDocument
{
    public LiveDocument() { } // Public constructor for System.Text.Json even though the model type is internal.

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("pk")]
    public string Pk { get; set; } = string.Empty;
    [JsonPropertyName("value")]
    public int Value { get; set; }
    [JsonPropertyName("ttl")]
    public int Ttl { get; set; }
    [JsonPropertyName("customerTag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CustomerTag { get; set; }
    [JsonPropertyName("nested")]
    public LiveNestedDocument? Nested { get; set; }
    [JsonPropertyName("_rid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Rid { get; set; }
    [JsonPropertyName("_self")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Self { get; set; }
    [JsonPropertyName("_etag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ETag { get; set; }
    [JsonPropertyName("_attachments")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Attachments { get; set; }
    [JsonPropertyName("_ts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? Timestamp { get; set; }
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

internal sealed class LiveNestedDocument
{
    public LiveNestedDocument() { }

    [JsonPropertyName("customerTag")]
    public string? CustomerTag { get; set; }
    [JsonPropertyName("ttl")]
    public int Ttl { get; set; }
}