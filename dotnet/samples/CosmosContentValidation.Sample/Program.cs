using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Identity;
using CosmosContentValidation;
using CosmosContentValidation.Sample.Providers;
using Microsoft.Azure.Cosmos;

namespace CosmosContentValidation.Sample;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            Console.WriteLine("""
                Cosmos content validation — PR1 point create/read sample (.NET 10)

                --help       Show help without reading keys or acquiring credentials.
                --offline    Run serializer/signature/tamper checks using ephemeral in-memory
                             keys. No Azure calls, credentials, key files, or key output.
                --tamper     ONLINE ONLY: deliberately patch this run's confirmed new items
                             with an unprotected client, then prove signed reads reject them.
                --direct     Use Direct rather than the sample's default Gateway mode.

                Online environment (no arguments performs the normal online demonstration):
                  COSMOS_RUN_LIVE_TESTS=1       Explicit authorization for live operations.
                  COSMOS_ENDPOINT              HTTPS Cosmos DB endpoint.
                  COSMOS_DATABASE              Existing dedicated database.
                  COSMOS_CONTAINER             Existing dedicated container, exactly /pk.
                  COSMOS_KEY                   Optional account key; otherwise DefaultAzureCredential.
                  CONTENT_SIGNING_KEY_FILE     Existing P-256 PKCS#8 PRIVATE KEY PEM file.
                  CONTENT_VERIFICATION_KEY_FILE Existing matching P-256 SPKI PUBLIC KEY PEM file.
                  CONTENT_KEY_ID               Locally trusted identifier shared by both providers.
                  CONTENT_IGNORED_PROPERTIES   Optional comma-delimited root names, e.g. ttl,customerTag.

                Provision resources and keys separately; this sample never generates key files.
                Both keys are loaded once and verified together BEFORE any network call/write.
                Ignored fields are unauthenticated, exact-case, root-only; id/pk/envelope cannot
                be ignored. For --tamper, leave the sample's 'value' field protected.
                No database/container provisioning or deletion. Only acknowledged new items are
                cleaned up; ambiguous writes report generated IDs for manual inspection.
                """);
            return 0;
        }

        try
        {
            Require(args.All(arg => arg is "--offline" or "--tamper" or "--direct"),
                "Unknown argument. Use --help; no argument values are echoed.");
            if (args.Contains("--offline", StringComparer.Ordinal))
            {
                Require(args.Length == 1, "Use --offline alone; it already includes local tamper checks.");
                RunOffline();
                return 0;
            }
            bool tamper = args.Contains("--tamper", StringComparer.Ordinal);
            Configuration configuration = Configuration.Load(tamper);
            using UnsafeEcdsaContentSigner signer = LoadSigner(configuration);
            using UnsafeEcdsaContentVerifier verifier = LoadVerifier(configuration);
            (ContentValidationProcessor writer, ContentValidationProcessor reader) = Processors(signer, verifier, configuration.Ignored);
            // Sign and materialize with the independent public-only reader. Merely importing two
            // valid PEM files is NOT evidence that the keys match. No Cosmos clients exist yet.
            try { RoundTrip(writer, reader, new SampleDocument("startup-" + Guid.NewGuid().ToString("N"), "startup")); }
            catch (ContentValidationException)
            {
                throw new SampleFailure("Startup sign/verify failed: the private/public keys must match under CONTENT_KEY_ID. No network call or write was made.");
            }
            Console.WriteLine("Startup: matching local keys verified; reader has public verification capability only.");
            if (configuration.Ignored.Length > 0)
                Console.WriteLine("Policy: additional root exclusions enabled. Excluded values are NOT authenticated; both clients use the same policy.");
            return await RunOnlineAsync(configuration, writer, reader, tamper,
                args.Contains("--direct", StringComparer.Ordinal) ? ConnectionMode.Direct : ConnectionMode.Gateway);
            // Clients are disposed within RunOnlineAsync BEFORE the caller-owned providers above.
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(SafeFailure(exception));
            return exception switch
            {
                ContentValidationException => 2,
                CosmosException => 3,
                AuthenticationFailedException => 4,
                _ => 1
            };
        }
    }

    private static (ContentValidationProcessor Writer, ContentValidationProcessor Reader) Processors(
        UnsafeEcdsaContentSigner signer, UnsafeEcdsaContentVerifier verifier, string[] ignored)
    {
        ContentValidationOptions options = new() { PartitionKeyPaths = ["/pk"], AdditionalIgnoredRootProperties = ignored };
        UnsafeInMemoryVerificationKeyResolver keys = new([verifier]);
        return (UnsafeSampleProviders.CreateProcessor(options, keys, signer),
            UnsafeSampleProviders.CreateProcessor(options, keys)); // No signer supplied to the reader.
    }

    private static UnsafeEcdsaContentSigner LoadSigner(Configuration configuration)
    {
        try { return new(configuration.KeyId, File.ReadAllText(configuration.PrivateKeyFile)); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException)
        { throw new SampleFailure("Cannot load CONTENT_SIGNING_KEY_FILE: supply one accessible, unencrypted PKCS#8 named P-256 PRIVATE KEY PEM block."); }
    }

    private static UnsafeEcdsaContentVerifier LoadVerifier(Configuration configuration)
    {
        try { return new(configuration.KeyId, File.ReadAllText(configuration.PublicKeyFile)); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException)
        { throw new SampleFailure("Cannot load CONTENT_VERIFICATION_KEY_FILE: supply one accessible SPKI named P-256 PUBLIC KEY PEM block (not a private key)."); }
    }

    private static void RunOffline()
    {
        // Temporary PEM strings are required by the current providers; never print or persist them.
        // Immutable strings cannot be explicitly zeroed. Crypto handles are deterministically disposed.
        using ECDsa ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using UnsafeEcdsaContentSigner signer = new("offline-ephemeral", ephemeral.ExportPkcs8PrivateKeyPem());
        using UnsafeEcdsaContentVerifier verifier = new("offline-ephemeral", ephemeral.ExportSubjectPublicKeyInfoPem());
        (ContentValidationProcessor writer, ContentValidationProcessor reader) = Processors(signer, verifier, []);
        SampleDocument document = new("offline-" + Guid.NewGuid().ToString("N"), "offline");
        RoundTrip(writer, reader, document);
        Console.WriteLine("PASS: typed serializer signs, public-only serializer verifies and materializes the model.");

        // Consume ToStream while its owner is alive; every FromStream input transfers to that serializer.
        using Stream signed = new ContentValidationSerializer(writer).ToStream(document);
        JsonObject wire = JsonNode.Parse(signed)!.AsObject();
        reader.Validate(Bytes(wire));
        signed.Position = 0;
        using JsonDocument replay = JsonDocument.Parse(signed);
        Require(replay.RootElement.GetProperty("id").GetString() == document.Id, "Offline stream replay failed.");
        Console.WriteLine("PASS: signed stream remains readable and replayable until its owner disposes it.");

        JsonObject serviceDocument = (JsonObject)wire.DeepClone();
        serviceDocument["_rid"] = "offline-service-id";
        serviceDocument["_self"] = "offline-service-link";
        serviceDocument["_etag"] = "offline-etag";
        serviceDocument["_attachments"] = "attachments/";
        serviceDocument["_ts"] = 1;
        ReadWire(reader, serviceDocument);
        Console.WriteLine("PASS: the five default root service metadata fields do not break validation.");

        JsonObject changed = (JsonObject)wire.DeepClone();
        changed["value"] = 8;
        ExpectFailure(ContentValidationFailure.InvalidSignature, () => ReadWire(reader, changed));
        JsonObject unsigned = (JsonObject)wire.DeepClone();
        unsigned.Remove(ContentValidationProcessor.SignaturePropertyName);
        ExpectFailure(ContentValidationFailure.MissingSignature, () => ReadWire(reader, unsigned));
        foreach (string name in new[] { "ttl", "customerTag" })
        {
            JsonObject rootChange = (JsonObject)wire.DeepClone();
            rootChange[name] = name == "ttl" ? JsonValue.Create(86400) : JsonValue.Create("changed");
            ExpectFailure(ContentValidationFailure.InvalidSignature, () => ReadWire(reader, rootChange));
        }
        ExpectFailure(ContentValidationFailure.SigningUnavailable, () =>
        {
            using Stream unexpected = new ContentValidationSerializer(reader).ToStream(document);
        });
        Console.WriteLine("PASS: tampering, unsigned content, and public-only writes fail with distinct content categories.");

        (ContentValidationProcessor customWriter, ContentValidationProcessor customReader) = Processors(signer, verifier, ["ttl", "customerTag"]);
        RoundTrip(customWriter, customReader, document);
        using Stream customSigned = new ContentValidationSerializer(customWriter).ToStream(document);
        JsonObject customWire = JsonNode.Parse(customSigned)!.AsObject();
        customWire["ttl"] = 86400;
        customWire["customerTag"] = "changed-without-signing";
        ReadWire(customReader, customWire);
        customWire.Remove("customerTag");
        ReadWire(customReader, customWire);
        customWire["customerTag"] = "added-without-signing";
        ReadWire(customReader, customWire);
        ExpectFailure(ContentValidationFailure.PolicyMismatch, () => ReadWire(reader, customWire));
        customWire["nested"]!["customerTag"] = "tampered";
        ExpectFailure(ContentValidationFailure.InvalidSignature, () => ReadWire(customReader, customWire));
        Console.WriteLine("PASS: custom root exclusions allow edits; nested same-name fields and local policy identity remain protected.");

        using ECDsa unrelated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using UnsafeEcdsaContentVerifier wrongVerifier = new(signer.KeyId, unrelated.ExportSubjectPublicKeyInfoPem());
        ContentValidationProcessor wrongReader = UnsafeSampleProviders.CreateProcessor(new(), new UnsafeInMemoryVerificationKeyResolver([wrongVerifier]));
        ExpectFailure(ContentValidationFailure.InvalidSignature, () => RoundTrip(writer, wrongReader, document));
        ContentValidationProcessor unknownReader = UnsafeSampleProviders.CreateProcessor(new(), new UnsafeInMemoryVerificationKeyResolver(Array.Empty<IContentVerifier>()));
        ExpectFailure(ContentValidationFailure.UnknownKey, () => ReadWire(unknownReader, wire));
        Console.WriteLine("PASS: mismatched key pairs and unknown key IDs fail before any online operation.");
        Console.WriteLine("Offline checks complete. No Azure clients, credentials, key files, or key material output were used.");
    }

    private static void RoundTrip(ContentValidationProcessor writer, ContentValidationProcessor reader, SampleDocument document)
    {
        // FromStream owns/disposes the ToStream result; do not return a stream from a disposed scope.
        Stream signed = new ContentValidationSerializer(writer).ToStream(document);
        SampleDocument result = new ContentValidationSerializer(reader).FromStream<SampleDocument>(signed);
        Require(result.Id == document.Id && result.Pk == document.Pk && result.Value == document.Value, "Signed model round-trip failed.");
    }

    private static ReadOnlySequence<byte> Bytes(JsonObject document) => new(JsonSerializer.SerializeToUtf8Bytes(document));

    private static void ReadWire(ContentValidationProcessor reader, JsonObject wire)
    {
        Stream input = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(wire), writable: false);
        _ = new ContentValidationSerializer(reader).FromStream<SampleDocument>(input);
    }

    private static void ExpectFailure(ContentValidationFailure expected, Action action)
    {
        try { action(); }
        catch (ContentValidationException exception) when (exception.Failure == expected) { return; }
        throw new SampleFailure($"Expected content failure {expected} was not observed.");
    }

    private static async Task<int> RunOnlineAsync(Configuration configuration, ContentValidationProcessor writer,
        ContentValidationProcessor reader, bool tamper, ConnectionMode mode)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
        // Authentication and transport I/O belong here, never inside the signer/verifier.
        TokenCredential? credential = configuration.AccountKey is null ? new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true,
            CredentialProcessTimeout = TimeSpan.FromSeconds(10),
            Retry = { MaxRetries = 0, NetworkTimeout = TimeSpan.FromSeconds(10) }
        }) : null;
        using CosmosClient rawClient = configuration.AccountKey is { } accountKey
            ? new(configuration.Endpoint, accountKey, ClientOptions(mode))
            : new(configuration.Endpoint, credential!, ClientOptions(mode));
        Container raw = rawClient.GetContainer(configuration.Database, configuration.Container);
        ContainerResponse metadata = await raw.ReadContainerAsync(cancellationToken: timeout.Token);
        Require(metadata.Resource.PartitionKeyPaths is { Count: 1 } paths && paths[0] == "/pk",
            "The dedicated container must have exactly the partition-key path /pk. No item write was made.");
        Console.WriteLine($"Container metadata: /pk verified independently; connection mode={mode}.");

        using ContentValidationClient writerClient = ProtectedClient(configuration, credential, writer, mode);
        using ContentValidationClient readerClient = ProtectedClient(configuration, credential, reader, mode);
        Container writes = writerClient.GetContainer(configuration.Database, configuration.Container);
        Container reads = readerClient.GetContainer(configuration.Database, configuration.Container);
        string prefix = Guid.NewGuid().ToString("N") + "-cv-sample";
        // The ledger contains ONLY this run's identities. Success, not a GUID alone, establishes ownership.
        OwnedItem[] items = [new(prefix + "-typed", prefix), new(prefix + "-stream", prefix)];
        bool primaryFailed = false;
        bool cleanupFailed;
        try
        {
            OwnedItem typedItem = items[0];
            SampleDocument model = new(typedItem.Id, typedItem.Pk);
            ItemResponse<SampleDocument> created = await CreateTypedAsync(writes, typedItem, model, timeout.Token);
            CheckTyped(created, typedItem, HttpStatusCode.Created);
            Console.WriteLine("Typed create: 201, returned model materialized and signature verified.");
            await ReadBothAsync(reads, typedItem, timeout.Token);

            OwnedItem streamItem = items[1];
            using (MemoryStream payload = new(JsonSerializer.SerializeToUtf8Bytes(new SampleDocument(streamItem.Id, streamItem.Pk)), writable: false))
            using (ResponseMessage response = await CreateStreamAsync(writes, streamItem, payload, timeout.Token))
            {
                response.EnsureSuccessStatusCode();
                Require(response.StatusCode == HttpStatusCode.Created, "Stream create did not return 201.");
                Require(payload.CanRead && payload.Position == 0, "Caller stream ownership/position was not preserved.");
                await ConsumeStreamAsync(response, streamItem, timeout.Token);
                Console.WriteLine("Stream create: 201, signed body consumed and replayed; caller input remains open.");
            }
            await ReadBothAsync(reads, streamItem, timeout.Token);

            // This is a local capability demonstration, not a service write attempt. Actual wrapper
            // rejection of both typed/stream writes is also exercised by the opt-in live suite.
            ExpectFailure(ContentValidationFailure.SigningUnavailable, () =>
            {
                using Stream unexpected = new ContentValidationSerializer(reader).ToStream(model);
            });
            Console.WriteLine("Public-only reader: signing refused (SigningUnavailable).");

            if (tamper)
            {
                foreach (OwnedItem item in items)
                {
                    Require(item.Confirmed, "Tampering requires a confirmed create from this run.");
                    // Intentionally unprotected TEST client. Never use this path for business writes.
                    // The pinned SDK does not support IfMatchEtag for patch. Isolation here relies
                    // on the dedicated container and this run's confirmed GUID-scoped identities.
                    using ResponseMessage patched = await raw.PatchItemStreamAsync(item.Id, item.PartitionKey,
                        [PatchOperation.Set("/value", 8)], new PatchItemRequestOptions { SessionToken = item.SessionToken }, timeout.Token);
                    if (patched.IsSuccessStatusCode) item.Observe(patched.Headers);
                    patched.EnsureSuccessStatusCode();
                    await ExpectTamperedReadsAsync(reads, item, timeout.Token);
                }
                Console.WriteLine("Explicit tamper demonstration: both own items patched; typed and stream reads rejected InvalidSignature.");
            }
        }
        catch
        {
            primaryFailed = true;
            throw;
        }
        finally
        {
            cleanupFailed = await CleanupAsync(raw, items);
            if (cleanupFailed && primaryFailed)
                ReportCleanup("Cleanup also failed; the original operation failure remains the primary error.");
        }
        if (cleanupFailed) return 5;
        Console.WriteLine("Online demonstration complete; all acknowledged creations were cleaned up.");
        return 0;
    }

    private static async Task<ItemResponse<SampleDocument>> CreateTypedAsync(Container container, OwnedItem item,
        SampleDocument document, CancellationToken token)
    {
        try
        {
            ItemResponse<SampleDocument> response = await container.CreateItemAsync(document, item.PartitionKey,
                new ItemRequestOptions { EnableContentResponseOnWrite = true }, token);
            if ((int)response.StatusCode is >= 200 and <= 299) item.Confirm(response.Headers);
            return response;
        }
        catch (Exception exception) { WarnAmbiguousCreate(item, exception); throw; }
    }

    private static async Task<ResponseMessage> CreateStreamAsync(Container container, OwnedItem item, Stream payload, CancellationToken token)
    {
        try
        {
            ResponseMessage response = await container.CreateItemStreamAsync(payload, item.PartitionKey,
                new ItemRequestOptions { EnableContentResponseOnWrite = true }, token);
            if (response.IsSuccessStatusCode) item.Confirm(response.Headers);
            else if (response.StatusCode == HttpStatusCode.Conflict)
                Console.Error.WriteLine($"Create conflict: id={item.Id}, pk={item.Pk}; not owned and will NOT be deleted. Inspect manually if caused by an unacknowledged retry.");
            else
                Console.Error.WriteLine($"Unsuccessful create: id={item.Id}, pk={item.Pk}, status={(int)response.StatusCode}; not owned. Inspect manually for a possibly committed write; no automatic deletion.");
            return response; // Body remains live until the caller disposes the response.
        }
        catch (Exception exception) { WarnAmbiguousCreate(item, exception); throw; }
    }

    private static void WarnAmbiguousCreate(OwnedItem item, Exception exception)
    {
        if (item.Confirmed) return;
        string reason = exception is CosmosException { StatusCode: HttpStatusCode.Conflict }
            ? "Create conflict: ownership NOT established."
            : "Create may have committed before its response/signature could be validated.";
        Console.Error.WriteLine($"WARNING: {reason} id={item.Id}, pk={item.Pk}. Inspect/clean up manually; this run will NOT patch/delete it.");
    }

    private static async Task ReadBothAsync(Container reader, OwnedItem item, CancellationToken token)
    {
        // Separate clients need the write session token to avoid reading an older version/404.
        ItemResponse<SampleDocument> typed = await reader.ReadItemAsync<SampleDocument>(item.Id, item.PartitionKey, item.ReadOptions(), token);
        CheckTyped(typed, item, HttpStatusCode.OK);
        using ResponseMessage streamed = await reader.ReadItemStreamAsync(item.Id, item.PartitionKey, item.ReadOptions(), token);
        streamed.EnsureSuccessStatusCode();
        Require(streamed.StatusCode == HttpStatusCode.OK, "Stream read did not return 200.");
        await ConsumeStreamAsync(streamed, item, token);
        Console.WriteLine("Public-only reads: typed model and replayable stream verified (200); service metadata preserved.");
    }

    private static void CheckTyped(ItemResponse<SampleDocument> response, OwnedItem item, HttpStatusCode expected)
    {
        SampleDocument result = response.Resource; // Native SDK materialization, not a status-only claim.
        Require(response.StatusCode == expected && result is not null && result.Id == item.Id && result.Pk == item.Pk
            && result.Value == 7 && !string.IsNullOrWhiteSpace(result.ETag) && result.ETag == response.Headers.ETag,
            "Typed response status, materialized content, or service ETag did not match expectations.");
    }

    private static async Task ConsumeStreamAsync(ResponseMessage response, OwnedItem item, CancellationToken token)
    {
        Stream content = response.Content;
        Require(content is not null && content.CanRead && content.CanSeek && content.Position == 0, "Signed response is not a live, rewound stream.");
        using JsonDocument first = await JsonDocument.ParseAsync(content!, cancellationToken: token);
        JsonElement root = first.RootElement;
        Require(root.GetProperty("id").GetString() == item.Id && root.GetProperty("pk").GetString() == item.Pk
            && root.GetProperty("value").GetInt32() == 7 && root.GetProperty("_etag").GetString() == response.Headers.ETag
            && root.TryGetProperty(ContentValidationProcessor.SignaturePropertyName, out _), "Signed stream content was not preserved.");
        content!.Position = 0;
        using JsonDocument replay = await JsonDocument.ParseAsync(content, cancellationToken: token);
        Require(JsonElement.DeepEquals(root, replay.RootElement), "Rewound response changed on replay.");
        content.Position = 0; // Borrow only; ResponseMessage still owns the body.
    }

    private static async Task ExpectTamperedReadsAsync(Container reader, OwnedItem item, CancellationToken token)
    {
        bool typedRejected = false;
        try
        {
            ItemResponse<SampleDocument> response = await reader.ReadItemAsync<SampleDocument>(item.Id, item.PartitionKey, item.ReadOptions(), token);
            _ = response.Resource;
        }
        catch (ContentValidationException exception) when (exception.Failure == ContentValidationFailure.InvalidSignature) { typedRejected = true; }
        Require(typedRejected, "Tampered typed read unexpectedly succeeded.");
        bool streamRejected = false;
        try
        {
            using ResponseMessage response = await reader.ReadItemStreamAsync(item.Id, item.PartitionKey, item.ReadOptions(), token);
            response.EnsureSuccessStatusCode();
        }
        catch (ContentValidationException exception) when (exception.Failure == ContentValidationFailure.InvalidSignature) { streamRejected = true; }
        Require(streamRejected, "Tampered stream read unexpectedly succeeded.");
    }

    private static async Task<bool> CleanupAsync(Container raw, OwnedItem[] items)
    {
        bool failed = false;
        foreach (OwnedItem item in items.Where(item => item.Confirmed))
        {
            try
            {
                using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(20)); // Independent of canceled main work.
                using ResponseMessage response = await raw.DeleteItemStreamAsync(item.Id, item.PartitionKey,
                    new ItemRequestOptions { SessionToken = item.SessionToken, IfMatchEtag = item.ETag }, timeout.Token);
                if (response.StatusCode is HttpStatusCode.NoContent or HttpStatusCode.NotFound)
                    ReportCleanup("Cleanup: own acknowledged item deleted or already absent.");
                else
                {
                    failed = true;
                    ReportCleanup($"Cleanup failed: id={item.Id}, pk={item.Pk}, status={(int)response.StatusCode}. Inspect manually; no unconditional retry.");
                }
            }
            catch (Exception exception)
            {
                failed = true;
                ReportCleanup($"Cleanup failed: id={item.Id}, pk={item.Pk}. {SafeFailure(exception)} Inspect manually.");
            }
        }
        return failed;
    }

    private static void ReportCleanup(string safeMessage)
    {
        try { Console.Error.WriteLine(safeMessage); }
        catch (IOException) { } // A closed output pipe must not stop cleanup or mask the original error.
        catch (ObjectDisposedException) { }
    }

    private static CosmosClientOptions ClientOptions(ConnectionMode mode) => new()
    {
        ApplicationName = "ContentValidation-PR1-Sample", ConnectionMode = mode, ConsistencyLevel = ConsistencyLevel.Session,
        RequestTimeout = TimeSpan.FromSeconds(10), MaxRetryAttemptsOnRateLimitedRequests = 0,
        MaxRetryWaitTimeOnRateLimitedRequests = TimeSpan.Zero, LimitToEndpoint = true, EnableContentResponseOnWrite = true
    };

    private static ContentValidationClient ProtectedClient(Configuration configuration, TokenCredential? credential,
        ContentValidationProcessor processor, ConnectionMode mode) => configuration.AccountKey is { } key
        ? ContentValidationClient.Create(configuration.Endpoint, key, processor, ClientOptions(mode))
        : ContentValidationClient.Create(configuration.Endpoint, credential!, processor, ClientOptions(mode));

    private static string SafeFailure(Exception exception) => exception switch
    {
        SampleFailure safe => safe.Message, // Only constant/test-owned messages enter SampleFailure.
        ContentValidationException content => $"Content validation failed: category={content.Failure}. No document or key material is logged.",
        CosmosException cosmos => $"Cosmos request failed: HTTP status={(int)cosmos.StatusCode}, substatus={cosmos.SubStatusCode}.",
        AuthenticationFailedException => "Authentication failed. Check the externally configured credential and data-plane permissions.",
        OperationCanceledException => "Operation canceled or exceeded its time budget.",
        ArgumentException => "Invalid local configuration. Check the endpoint, key ID, and ignored-property policy; identity fields cannot be ignored.",
        _ => $"Operation failed: type={exception.GetType().Name}. Exception details are suppressed to avoid exposing sensitive values."
    };

    private static void Require(bool condition, string safeMessage)
    {
        if (!condition) throw new SampleFailure(safeMessage);
    }

    private sealed class SampleFailure(string safeMessage) : Exception(safeMessage);

    private sealed class OwnedItem(string id, string pk)
    {
        internal string Id { get; } = id;
        internal string Pk { get; } = pk;
        internal PartitionKey PartitionKey => new(Pk);
        internal bool Confirmed { get; private set; }
        internal string? SessionToken { get; private set; }
        internal string? ETag { get; private set; }
        internal void Confirm(Headers headers) { Confirmed = true; Observe(headers); }
        internal void Observe(Headers headers) { SessionToken = headers["x-ms-session-token"]; ETag = headers.ETag; }
        internal ItemRequestOptions ReadOptions()
        {
            Require(Confirmed && !string.IsNullOrWhiteSpace(SessionToken), "A confirmed create and session token are required for cross-client reads.");
            return new() { SessionToken = SessionToken };
        }
    }

    // Do not use a record for secret-bearing configuration: its generated ToString would expose values.
    private sealed class Configuration
    {
        internal required string Endpoint { get; init; }
        internal required string Database { get; init; }
        internal required string Container { get; init; }
        internal string? AccountKey { get; init; }
        internal required string PrivateKeyFile { get; init; }
        internal required string PublicKeyFile { get; init; }
        internal required string KeyId { get; init; }
        internal required string[] Ignored { get; init; }

        internal static Configuration Load(bool tamper)
        {
            Require(Environment.GetEnvironmentVariable("COSMOS_RUN_LIVE_TESTS") == "1", "Online operations require COSMOS_RUN_LIVE_TESTS=1. Use --offline or --help without credentials.");
            string[] required = ["COSMOS_ENDPOINT", "COSMOS_DATABASE", "COSMOS_CONTAINER", "CONTENT_SIGNING_KEY_FILE", "CONTENT_VERIFICATION_KEY_FILE", "CONTENT_KEY_ID"];
            string[] missing = required.Where(name => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name))).ToArray();
            Require(missing.Length == 0, "Required environment variables are missing: " + string.Join(", ", missing) + ". No network request was made.");
            string endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT")!;
            Require(Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) && uri.Scheme == Uri.UriSchemeHttps
                && string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment),
                "COSMOS_ENDPOINT must be an absolute HTTPS endpoint without embedded credentials, query, or fragment.");
            string[] ignored = (Environment.GetEnvironmentVariable("CONTENT_IGNORED_PROPERTIES") ?? string.Empty)
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
            Require(!tamper || !ignored.Contains("value", StringComparer.Ordinal), "The --tamper demonstration requires 'value' to remain signed; remove it from CONTENT_IGNORED_PROPERTIES.");
            string? key = Environment.GetEnvironmentVariable("COSMOS_KEY");
            return new()
            {
                Endpoint = endpoint, Database = Environment.GetEnvironmentVariable("COSMOS_DATABASE")!, Container = Environment.GetEnvironmentVariable("COSMOS_CONTAINER")!,
                AccountKey = string.IsNullOrWhiteSpace(key) ? null : key,
                PrivateKeyFile = Environment.GetEnvironmentVariable("CONTENT_SIGNING_KEY_FILE")!, PublicKeyFile = Environment.GetEnvironmentVariable("CONTENT_VERIFICATION_KEY_FILE")!,
                KeyId = Environment.GetEnvironmentVariable("CONTENT_KEY_ID")!, Ignored = ignored
            };
        }
    }
}

internal sealed class SampleDocument
{
    public SampleDocument() { }
    public SampleDocument(string id, string pk) { Id = id; Pk = pk; }
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("pk")]
    public string Pk { get; set; } = string.Empty;
    [JsonPropertyName("value")]
    public int Value { get; set; } = 7;
    [JsonPropertyName("ttl")]
    public int Ttl { get; set; } = -1; // Disable item expiry even when a container has a default TTL.
    [JsonPropertyName("customerTag")]
    public string CustomerTag { get; set; } = "example";
    [JsonPropertyName("nested")]
    public Dictionary<string, string> Nested { get; set; } = new() { ["customerTag"] = "signed-nested-value" };
    [JsonPropertyName("_etag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ETag { get; set; }
}