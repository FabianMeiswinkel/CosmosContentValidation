using System.Net;
using System.Runtime.ExceptionServices;
using Azure.Core;
using Azure.Identity;
using Microsoft.Azure.Cosmos;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace CosmosContentValidation.LiveTests;

/// <summary>A safe assertion containing only test-owned text, never an underlying exception.</summary>
internal sealed class LiveTestFailure(string message) : XunitException(message) { }

internal static class LiveCheck
{
    internal static void Require(bool condition, string safeMessage)
    {
        if (!condition) throw new LiveTestFailure(safeMessage);
    }

    internal static LiveTestFailure Sanitize(Exception exception) => exception switch
    {
        LiveTestFailure safe => safe,
        CosmosException cosmos => new($"Cosmos request failed: status={(int)cosmos.StatusCode}, substatus={cosmos.SubStatusCode}."),
        ContentValidationException validation => new($"Content validation failed: reason={validation.Failure}."),
        AuthenticationFailedException => new($"Authentication failed: type={exception.GetType().Name}."),
        OperationCanceledException => new($"Operation canceled: type={exception.GetType().Name}."),
        _ => new($"Unexpected failure: type={exception.GetType().Name}.")
    };

    internal static void Status(HttpStatusCode actual, HttpStatusCode expected) => Require(
        actual == expected, $"Unexpected HTTP status: expected={(int)expected}, actual={(int)actual}.");

    internal static void ItemHeaders(Headers headers)
    {
        Require(!string.IsNullOrWhiteSpace(headers.ETag), "Item response omitted ETag.");
        Require(!string.IsNullOrWhiteSpace(headers.ActivityId), "Item response omitted ActivityId.");
        Require(double.IsFinite(headers.RequestCharge) && headers.RequestCharge > 0, "Item response omitted a positive finite request charge.");
        Require(!string.IsNullOrWhiteSpace(headers["x-ms-session-token"]), "Item response omitted the session token required for cross-client reads.");
    }
}

/// <summary>Never use a record here: its generated ToString would expose configuration.</summary>
internal sealed class LiveConfiguration
{
    private readonly string endpoint;
    private readonly string? key;
    private readonly TokenCredential? credential;
    internal string Database { get; }
    internal string Container { get; }

    private LiveConfiguration(string endpoint, string database, string container, string? key)
    {
        this.endpoint = endpoint;
        Database = database;
        Container = container;
        this.key = key;
        if (key is null)
        {
            credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ExcludeInteractiveBrowserCredential = true,
                CredentialProcessTimeout = TimeSpan.FromSeconds(10),
                Retry = { MaxRetries = 0, NetworkTimeout = TimeSpan.FromSeconds(10) }
            });
        }
    }

    internal static LiveConfiguration Load()
    {
        LiveCheck.Require(LiveTheoryAttribute.IsEnabled, "Live tests were not explicitly enabled.");
        string[] names = ["COSMOS_ENDPOINT", "COSMOS_DATABASE", "COSMOS_CONTAINER"];
        string?[] values = names.Select(Environment.GetEnvironmentVariable).ToArray();
        string[] missing = names.Where((_, index) => string.IsNullOrWhiteSpace(values[index])).ToArray();
        LiveCheck.Require(missing.Length == 0,
            "Live tests are enabled but required environment variables are missing: " + string.Join(", ", missing) + ". No network request was made.");
        LiveCheck.Require(Uri.TryCreate(values[0], UriKind.Absolute, out Uri? uri)
            && uri.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment),
            "COSMOS_ENDPOINT must be an absolute HTTPS endpoint without embedded credentials, query, or fragment. No network request was made.");
        string? key = Environment.GetEnvironmentVariable("COSMOS_KEY");
        return new LiveConfiguration(values[0]!, values[1]!, values[2]!, string.IsNullOrWhiteSpace(key) ? null : key);
    }

    internal CosmosClient CreateRawClient(ConnectionMode mode) => key is not null
        ? new CosmosClient(endpoint, key, Options(mode))
        : new CosmosClient(endpoint, credential!, Options(mode));

    internal ContentValidationClient CreateProtectedClient(ConnectionMode mode, ContentValidationProcessor processor) => key is not null
        ? ContentValidationClient.Create(endpoint, key, processor, Options(mode))
        : ContentValidationClient.Create(endpoint, credential!, processor, Options(mode));

    private static CosmosClientOptions Options(ConnectionMode mode) => new()
    {
        ApplicationName = "ContentValidation-PR2-LiveTests",
        ConnectionMode = mode,
        ConsistencyLevel = ConsistencyLevel.Session,
        RequestTimeout = TimeSpan.FromSeconds(10),
        MaxRetryAttemptsOnRateLimitedRequests = 0,
        MaxRetryWaitTimeOnRateLimitedRequests = TimeSpan.Zero,
        LimitToEndpoint = true,
        EnableContentResponseOnWrite = true
    };
}

/// <summary>All IDs, including unsuccessful/ambiguous attempts, stay in the per-test ledger.</summary>
internal sealed class LiveItem(string id, string partitionKey)
{
    internal string Id { get; } = id;
    internal string Pk { get; } = partitionKey;
    internal PartitionKey PartitionKey => new(Pk);
    internal bool Attempted { get; set; }
    internal bool Confirmed { get; set; }
    internal string? SessionToken { get; set; }
    internal string? ETag { get; set; }

    internal ItemRequestOptions ReadOptions()
    {
        LiveCheck.Require(Confirmed, "Read requires this test's acknowledged create.");
        LiveCheck.Require(!string.IsNullOrWhiteSpace(SessionToken), "A confirmed write must supply a session token before a cross-client operation.");
        return new ItemRequestOptions { SessionToken = SessionToken };
    }
}

/// <summary>
/// No resource provisioning. The raw client can tamper/delete only ledger entries whose
/// create returned success. A create that throws after commit is ambiguous and is NEVER auto-deleted.
/// </summary>
internal sealed class LiveTestScope(ITestOutputHelper output, CancellationToken token)
{
    private readonly string prefix = Guid.NewGuid().ToString("N") + "-cv-live";
    private readonly List<LiveItem> items = [];
    private CosmosClient? rawClient;
    private ContentValidationClient? writerClient;
    private ContentValidationClient? readerClient;
    private bool outputFailed;
    private Container raw = null!;
    internal Container Writer { get; private set; } = null!;
    internal Container Reader { get; private set; } = null!;
    internal ContentValidationProcessor ReaderProcessor { get; private set; } = null!;
    internal CancellationToken Token { get; } = token;

    internal static async Task RunAsync(LiveSigningFixture fixture, ITestOutputHelper output, ConnectionMode mode,
        bool customPolicy, Func<LiveTestScope, Task> test)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
        LiveTestScope scope = new(output, timeout.Token);
        LiveTestFailure? primary = null;
        bool cleanupFailed = false;
        try
        {
            await scope.InitializeAsync(fixture, mode, customPolicy);
            await test(scope);
        }
        catch (Exception exception)
        {
            // Retain only a safe failure. Never attach the SDK/authentication exception as InnerException.
            primary = LiveCheck.Sanitize(exception);
        }
        finally
        {
            try { cleanupFailed = await scope.CleanupAsync(); }
            catch (Exception exception)
            {
                cleanupFailed = true;
                scope.Log("Cleanup infrastructure failed: " + LiveCheck.Sanitize(exception).Message);
            }
            finally
            {
                cleanupFailed |= scope.DisposeClients();
                cleanupFailed |= scope.outputFailed;
            }
        }

        if (primary is not null) ExceptionDispatchInfo.Capture(primary).Throw();
        LiveCheck.Require(!cleanupFailed, "Test assertions passed, but cleanup/client disposal/output failed; inspect the sanitized test output for generated item identifiers.");
        scope.Log("Live test passed; all confirmed test items were cleaned up.");
        LiveCheck.Require(!scope.outputFailed, "The test output sink failed; cleanup completed, but outcome reporting was unavailable.");
    }

    private async Task InitializeAsync(LiveSigningFixture fixture, ConnectionMode mode, bool customPolicy)
    {
        LiveConfiguration configuration = LiveConfiguration.Load(); // Validate ALL required values before clients/credentials do I/O.
        rawClient = configuration.CreateRawClient(mode);
        raw = rawClient.GetContainer(configuration.Database, configuration.Container);
        ContainerResponse response = await raw.ReadContainerAsync(cancellationToken: Token);
        LiveCheck.Status(response.StatusCode, HttpStatusCode.OK);
        LiveCheck.Require(response.Resource?.PartitionKeyPaths is { Count: 1 } paths
            && string.Equals(paths[0], "/pk", StringComparison.Ordinal),
            "The preprovisioned dedicated live-test container must have exactly one partition-key path: /pk. No protected client was created.");

        // Only after independent service metadata verification may protected processors/clients be set up.
        (ContentValidationProcessor writer, ContentValidationProcessor reader) = fixture.CreateProcessors(customPolicy);
        ReaderProcessor = reader;
        LiveCheck.Require(writer.CanSign && !reader.CanSign, "Writer/reader signing capabilities are not separated.");
        writerClient = configuration.CreateProtectedClient(mode, writer);
        Writer = writerClient.GetContainer(configuration.Database, configuration.Container);
        readerClient = configuration.CreateProtectedClient(mode, reader);
        Reader = readerClient.GetContainer(configuration.Database, configuration.Container);
        Log($"Verified /pk container; mode={mode}; policy={(customPolicy ? "custom-root" : "default")}; reader is public-only.");
    }

    internal LiveItem NewItem(string? partitionSuffix = null)
    {
        LiveCheck.Require(items.Count < 2, "The per-test item budget is two identities, including failed attempts.");
        LiveItem item = new(prefix + "-" + Guid.NewGuid().ToString("N"),
            partitionSuffix is null ? prefix : prefix + "-" + partitionSuffix);
        items.Add(item); // Register generated identity BEFORE any attempt, including public-only attempts.
        return item;
    }

    private void BeginCreate(LiveItem item)
    {
        LiveCheck.Require(items.Contains(item) && !item.Attempted, "Create requires a fresh identity generated by this test.");
        item.Attempted = true;
    }

    internal async Task<ItemResponse<LiveDocument>> CreateTypedAsync(LiveItem item, LiveDocument document, bool publicOnly = false)
    {
        BeginCreate(item);
        try
        {
            ItemResponse<LiveDocument> response = await (publicOnly ? Reader : Writer).CreateItemAsync(
                document, item.PartitionKey, new ItemRequestOptions { EnableContentResponseOnWrite = true }, Token);
            if ((int)response.StatusCode is >= 200 and <= 299)
            {
                item.Confirmed = true; // FIRST action on acknowledged success, before headers/Resource/assertions.
                ObserveWrite(item, response.Headers);
            }
            return response;
        }
        catch (Exception exception)
        {
            WarnUnacknowledgedCreate(item, exception);
            throw;
        }
    }

    internal async Task<ResponseMessage> CreateStreamAsync(LiveItem item, Stream payload, bool publicOnly = false)
    {
        BeginCreate(item);
        ResponseMessage? response = null;
        try
        {
            response = await (publicOnly ? Reader : Writer).CreateItemStreamAsync(
                payload, item.PartitionKey, new ItemRequestOptions { EnableContentResponseOnWrite = true }, Token);
            if (response.IsSuccessStatusCode)
            {
                item.Confirmed = true; // FIRST action on acknowledged success; ownership is independent of parsing.
                ObserveWrite(item, response.Headers);
            }
            else
            {
                Log($"Create not acknowledged: generated id={item.Id}, pk={item.Pk}, status={(int)response.StatusCode}. Ownership NOT established; inspect manually for a possibly committed write. No automatic patch/deletion.");
            }
            return response; // Caller owns the response AND its still-live body.
        }
        catch (Exception exception)
        {
            WarnUnacknowledgedCreate(item, exception);
            try { response?.Dispose(); }
            catch (Exception disposalFailure) { Log("Create response disposal failed: " + LiveCheck.Sanitize(disposalFailure).Message); }
            throw;
        }
    }

    internal async Task<ItemResponse<LiveDocument>> UpsertTypedAsync(LiveItem item, LiveDocument document,
        bool enableContentResponse = true)
    {
        bool inserting = !item.Attempted;
        if (inserting) BeginCreate(item);
        else LiveCheck.Require(items.Contains(item) && item.Confirmed, "Upsert update requires this test's acknowledged item.");
        try
        {
            ItemResponse<LiveDocument> response = await Writer.UpsertItemAsync(document, item.PartitionKey,
                new ItemRequestOptions { EnableContentResponseOnWrite = enableContentResponse }, Token);
            if ((int)response.StatusCode is >= 200 and <= 299)
            {
                if (inserting) item.Confirmed = true;
                ObserveWrite(item, response.Headers);
            }
            return response;
        }
        catch (Exception exception)
        {
            if (inserting) WarnUnacknowledgedCreate(item, exception);
            throw;
        }
    }

    internal async Task<ResponseMessage> UpsertStreamAsync(LiveItem item, Stream payload,
        bool enableContentResponse = true)
    {
        bool inserting = !item.Attempted;
        if (inserting) BeginCreate(item);
        else LiveCheck.Require(items.Contains(item) && item.Confirmed, "Upsert update requires this test's acknowledged item.");
        ResponseMessage? response = null;
        try
        {
            response = await Writer.UpsertItemStreamAsync(payload, item.PartitionKey,
                new ItemRequestOptions { EnableContentResponseOnWrite = enableContentResponse }, Token);
            if (response.IsSuccessStatusCode)
            {
                if (inserting) item.Confirmed = true;
                ObserveWrite(item, response.Headers);
            }
            return response;
        }
        catch (Exception exception)
        {
            if (inserting) WarnUnacknowledgedCreate(item, exception);
            try { response?.Dispose(); }
            catch (Exception disposalFailure) { Log("Upsert response disposal failed: " + LiveCheck.Sanitize(disposalFailure).Message); }
            throw;
        }
    }

    private void WarnUnacknowledgedCreate(LiveItem item, Exception exception)
    {
        if (item.Confirmed || exception is ContentValidationException { Failure: ContentValidationFailure.SigningUnavailable }) return;
        if (exception is CosmosException { StatusCode: HttpStatusCode.Conflict })
        {
            Log($"Create conflict: generated id={item.Id}, pk={item.Pk}; ownership NOT established, no automatic deletion. Inspect manually if this followed an unacknowledged retry.");
            return;
        }
        Log($"WARNING: create may have committed without acknowledgement: generated id={item.Id}, pk={item.Pk}. Inspect/clean up manually; this test will NOT patch/delete this identity. {LiveCheck.Sanitize(exception).Message}");
    }

    private static void ObserveWrite(LiveItem item, Headers headers)
    {
        item.SessionToken = headers["x-ms-session-token"];
        item.ETag = headers.ETag;
    }

    internal async Task TamperAsync(LiveItem item, params PatchOperation[] operations)
    {
        LiveCheck.Require(items.Contains(item) && item.Confirmed, "Raw patch is limited to this test's acknowledged creates.");
        ItemRequestOptions session = item.ReadOptions();
        // Patch IfMatchEtag is unsupported by the pinned SDK. Use only this isolated test's
        // confirmed GUID-scoped identities; ETag preconditions are supported on cleanup deletes.
        using ResponseMessage response = await raw.PatchItemStreamAsync(item.Id, item.PartitionKey, operations,
            new PatchItemRequestOptions { SessionToken = session.SessionToken }, Token);
        if (response.IsSuccessStatusCode) ObserveWrite(item, response.Headers); // Update even if a later assertion fails.
        LiveCheck.Status(response.StatusCode, HttpStatusCode.OK);
        LiveCheck.ItemHeaders(response.Headers);
        // Do not deserialize this deliberately unsigned response. Response disposal owns its body.
    }

    private async Task<bool> CleanupAsync()
    {
        bool failed = false;
        int cleaned = 0;
        foreach (LiveItem item in items.Where(item => item.Confirmed))
        {
            // Each confirmed identity gets an independent budget, even after test cancellation/failure.
            try
            {
                using CancellationTokenSource cleanupTimeout = new(TimeSpan.FromSeconds(20));
                using ResponseMessage response = await raw.DeleteItemStreamAsync(item.Id, item.PartitionKey,
                    new ItemRequestOptions { SessionToken = item.SessionToken, IfMatchEtag = item.ETag }, cleanupTimeout.Token);
                if (response.StatusCode is HttpStatusCode.NoContent or HttpStatusCode.NotFound)
                {
                    cleaned++;
                    continue;
                }
                failed = true;
                Log($"Cleanup failed: generated id={item.Id}, pk={item.Pk}, status={(int)response.StatusCode}. Inspect manually; no unconditional retry (ownership may have changed).");
            }
            catch (Exception exception)
            {
                failed = true;
                Log($"Cleanup failed: generated id={item.Id}, pk={item.Pk}. {LiveCheck.Sanitize(exception).Message} Inspect manually.");
            }
        }
        Log($"Item ledger: generated={items.Count}, attempted={items.Count(item => item.Attempted)}, confirmed={items.Count(item => item.Confirmed)}, cleaned-or-already-absent={cleaned}.");
        return failed;
    }

    private bool DisposeClients()
    {
        bool failed = false;
        foreach (CosmosClient? client in new CosmosClient?[] { readerClient, writerClient, rawClient })
        {
            try { client?.Dispose(); }
            catch (Exception exception)
            {
                failed = true;
                Log("Client disposal failed: " + LiveCheck.Sanitize(exception).Message);
            }
        }
        return failed;
    }

    private void Log(string safeMessage)
    {
        try { output.WriteLine(safeMessage); }
        catch { outputFailed = true; } // Output-sink failures must not stop cleanup or replace the primary error.
    }
}