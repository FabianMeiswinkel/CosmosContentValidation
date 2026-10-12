using System.Buffers;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using CosmosContentValidation.Sample;
using CosmosContentValidation.Sample.Providers;
using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Scripts;
using Microsoft.IO;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class CosmosWrapperTests
{
    private const string Endpoint = "https://localhost:8081";
    private const string Key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private const string Document = "{\"id\":\"one\",\"pk\":\"p\",\"value\":7}";
    private static readonly PartitionKey Pk = new("p");
    private static readonly Type[] SdkOwnedItemTypes =
    [
        typeof(AccountProperties), typeof(DatabaseProperties), typeof(ContainerProperties),
        typeof(PermissionProperties), typeof(StoredProcedureProperties), typeof(TriggerProperties),
        typeof(UserDefinedFunctionProperties), typeof(UserProperties), typeof(ConflictProperties),
        typeof(ThroughputProperties), typeof(ClientEncryptionKeyProperties)
    ];

    public static IEnumerable<object[]> SdkOwnedItemTargets => SdkOwnedItemTypes.Select(type => new object[] { type });

    [Fact]
    public void FactoriesInstallSerializerAndPreserveGuardedHierarchy()
    {
        using Harness h = new();
        using ContentValidationClient keyClient = ContentValidationClient.Create(Endpoint, Key, h.Processor);
        using ContentValidationClient tokenClient = ContentValidationClient.Create(Endpoint, new OfflineCredential(), h.Processor);
        foreach (ContentValidationClient client in new[] { keyClient, tokenClient })
        {
            Assert.Equal(new Uri(Endpoint), client.Endpoint);
            Assert.IsType<ContentValidationSerializer>(client.ClientOptions.Serializer);
            Assert.NotNull(client.ResponseFactory);
            Database db = client.GetDatabase("db");
            Container container = db.GetContainer("items");
            Assert.IsType<ContentValidationDatabase>(db);
            Assert.IsType<ContentValidationContainer>(container);
            Assert.Equal("db", db.Id);
            Assert.Equal("items", container.Id);
            Assert.Same(client, db.Client);
            Assert.Same(db, container.Database);
            Assert.Same(client, client.GetContainer("db", "items").Database.Client);
        }
    }

    [Fact]
    public void NativeResponseFactoryUsesInstalledSerializerAndSkipsEmptyDeleteBodies()
    {
        using Harness h = new();
        using ContentValidationClient client = ContentValidationClient.Create(Endpoint, Key, h.Processor);
        using RecyclableMemoryStream signed = h.SignDocument();
        ItemResponse<Dictionary<string, object>> valid = client.ResponseFactory.CreateItemResponse<Dictionary<string, object>>(
            Response(HttpStatusCode.OK, h.Processor.Buffers.Read(signed)));
        Assert.Equal("one", valid.Resource["id"].ToString());
        Assert.False(valid.Resource.ContainsKey("_contentValidation"));
        TrackingStream unsigned = new(Document);
        Assert.Throws<ContentValidationException>(() => client.ResponseFactory.CreateItemResponse<JsonElement>(Response(HttpStatusCode.OK, unsigned)));
        Assert.True(unsigned.DisposeCalls >= 1);
        Assert.Equal(HttpStatusCode.NoContent, client.ResponseFactory.CreateItemResponse<JsonElement>(Response(HttpStatusCode.NoContent)).StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeResponseFactoryBypassesSdkDtoValidationButGuardedItemReadRejects(bool removeSignature)
    {
        using Harness h = new();
        using ContentValidationClient client = ContentValidationClient.Create(Endpoint, Key, h.Processor);
        string content = Document;
        if (removeSignature)
        {
            JsonObject document = JsonNode.Parse(h.SignedDocumentText())!.AsObject();
            Assert.True(document.Remove("_contentValidation"));
            content = document.ToJsonString();
        }

        // The native response factory is deliberately not a guarded item API. Cosmos 3.63.2
        // materializes SDK DTOs using its properties serializer, even with ours installed.
        TrackingStream nativeBody = new(content);
        ItemResponse<DatabaseProperties> unguarded = client.ResponseFactory.CreateItemResponse<DatabaseProperties>(
            Response(HttpStatusCode.OK, nativeBody));
        Assert.Equal("one", unguarded.Resource.Id);
        Assert.True(nativeBody.DisposeCalls >= 1);
        TrackingStream customBody = new(content);
        ContentValidationException missing = Assert.Throws<ContentValidationException>(() =>
            client.ResponseFactory.CreateItemResponse<JsonElement>(Response(HttpStatusCode.OK, customBody)));
        Assert.Equal(ContentValidationFailure.MissingSignature, missing.Failure);
        Assert.True(customBody.DisposeCalls >= 1);

        using TrackingResponse response = Response(HttpStatusCode.OK, new TrackingStream(content));
        h.Inner.ReadResponse = response;
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.ReadItemAsync<DatabaseProperties>("one", Pk));
        Assert.Equal(0, h.Inner.Calls);
        Assert.Equal(0, Assert.IsType<TrackingStream>(response.Content).ReadCalls);
        Assert.Equal(0, response.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void PinnedSdkOwnedPublicTypesRequireReviewWhenSerializerRoutingChanges()
    {
        // Reflection stays in tests. Arrays are handled separately by SDK feed routing;
        // the point-operation guard intentionally compares the direct generic target only.
        Type core = typeof(CosmosClient).Assembly.GetType("Microsoft.Azure.Cosmos.CosmosSerializerCore", throwOnError: true)!;
        MethodInfo predicate = core.GetMethod("IsInputTypeInternal", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)!;
        Type[] sdkOwned = core.Assembly.GetExportedTypes()
            .Where(type => (bool)predicate.Invoke(null, [type])!).ToArray();
        Assert.Equal(SdkOwnedItemTypes.OrderBy(type => type.FullName), sdkOwned.OrderBy(type => type.FullName));
    }

    [Theory]
    [MemberData(nameof(SdkOwnedItemTargets))]
    public void SdkOwnedGenericTargetsRejectBeforeEveryInnerItemCall(Type target)
    {
        using Harness h = new();
        foreach (string operation in new[] { "CreateItemAsync", "ReadItemAsync", "DeleteItemAsync" })
        {
            MethodInfo method = typeof(Container).GetMethods().Single(method => method.Name == operation).MakeGenericMethod(target);
            // Some DTOs have no public constructor. Their state must never be inspected:
            // rejection depends on the generic target and must precede any inner submission.
            object item = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(target);
            object?[] arguments = [operation == "CreateItemAsync" ? item : "one", Pk, null, CancellationToken.None];
            TargetInvocationException failure = Assert.Throws<TargetInvocationException>(() => method.Invoke(h.Container, arguments));
            Assert.IsType<NotSupportedException>(failure.InnerException);
            Assert.Equal(0, h.Inner.Calls);
        }
        Assert.Equal(0, h.Signer.Calls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void DisposalOwnsOnlyInnerClientAndIsIdempotent()
    {
        using Harness h = new();
        FakeClient inner = new();
        ContentValidationClient client = new(inner, h.Processor);
        client.Dispose();
        client.Dispose();
        Assert.Equal(1, inner.DisposeCalls);
        using RecyclableMemoryStream signed = h.SignDocument();
        h.Processor.Validate(signed.GetReadOnlySequence());
    }

    [Fact]
    public void OptionsAreDetachedAndUnsafeMutationsCannotEnableBulkOrHandlers()
    {
        using Harness h = new();
        List<string> regions = [Regions.EastUS];
        CosmosClientOptions options = new()
        {
            ApplicationName = "guard-test", ApplicationPreferredRegions = regions,
            ConnectionMode = ConnectionMode.Gateway, RequestTimeout = TimeSpan.FromSeconds(12),
            MaxRetryAttemptsOnRateLimitedRequests = 2, EnableContentResponseOnWrite = false
        };
        using ContentValidationClient client = ContentValidationClient.Create(Endpoint, Key, h.Processor, options);
        regions.Add(Regions.WestUS);
        options.AllowBulkExecution = true;
        options.CustomHandlers.Add(new PassThroughHandler());
        options.EnableContentResponseOnWrite = true;
        CosmosClientOptions detached = client.ClientOptions;
        detached.AllowBulkExecution = true;
        detached.CustomHandlers.Add(new PassThroughHandler());
        detached.Serializer = new PlainSerializer();
        CosmosClientOptions again = client.ClientOptions;
        Assert.False(again.AllowBulkExecution);
        Assert.Empty(again.CustomHandlers);
        Assert.False(again.EnableContentResponseOnWrite);
        Assert.Single(again.ApplicationPreferredRegions);
        Assert.Equal("guard-test", again.ApplicationName);
        Assert.Equal(TimeSpan.FromSeconds(12), again.RequestTimeout);
        Assert.Equal(ConnectionMode.Gateway, again.ConnectionMode);
        Assert.IsType<ContentValidationSerializer>(again.Serializer);
    }

    [Fact]
    public void FactoriesRejectUnsafeOrUnsupportedOptionsWithoutConnecting()
    {
        using Harness h = new();
        Action<CosmosClientOptions>[] changes =
        [
            o => o.AllowBulkExecution = true,
            o => o.Serializer = new PlainSerializer(),
            o => o.SerializerOptions = new CosmosSerializationOptions(),
            o => o.UseSystemTextJsonSerializerWithOptions = new JsonSerializerOptions(),
            o => o.CustomHandlers.Add(new PassThroughHandler()),
            o => o.HttpClientFactory = () => throw new InvalidOperationException("Must not create a transport"),
            o => o.ServerCertificateCustomValidationCallback = (_, _, _) => true,
            o => o.AccountInitializationCustomEndpoints = [new Uri(Endpoint)],
            o => o.GatewayModeMaxConnectionLimit = 51,
            o => o.MaxTcpConnectionsPerEndpoint = 10,
            o => o.ThroughputBucket = 1,
            o => o.CosmosClientTelemetryOptions.QueryTextMode = QueryTextMode.All
        ];
        foreach (Action<CosmosClientOptions> change in changes)
        {
            CosmosClientOptions options = new();
            change(options);
            Assert.Throws<NotSupportedException>(() => ContentValidationClient.Create(Endpoint, Key, h.Processor, options));
            Assert.Throws<NotSupportedException>(() => ContentValidationClient.Create(Endpoint, new OfflineCredential(), h.Processor, options));
        }
        Assert.Throws<NotSupportedException>(() => ContentValidationClient.Create(Endpoint, Key, h.Processor, new DerivedClientOptions()));
    }

    [Fact]
    public void PinnedClientOptionSurfaceRequiresReviewWhenSdkAddsSettings()
    {
        // Force review of the explicit allowlist and public TLS callback presence check on SDK upgrades.
        string[] reviewed =
        [
            "ApplicationName", "ApplicationRegion", "ApplicationPreferredRegions", "AccountInitializationCustomEndpoints",
            "GatewayModeMaxConnectionLimit", "RequestTimeout", "TokenCredentialBackgroundRefreshInterval", "CustomHandlers",
            "ConnectionMode", "ConsistencyLevel", "ReadConsistencyStrategy", "PriorityLevel", "MaxRetryAttemptsOnRateLimitedRequests",
            "MaxRetryWaitTimeOnRateLimitedRequests", "EnableContentResponseOnWrite", "UseSystemTextJsonSerializerWithOptions",
            "IdleTcpConnectionTimeout", "OpenTcpConnectionTimeout", "MaxRequestsPerTcpConnection", "MaxTcpConnectionsPerEndpoint",
            "PortReuseMode", "WebProxy", "SerializerOptions", "Serializer", "LimitToEndpoint", "AllowBulkExecution",
            "EnableTcpConnectionEndpointRediscovery", "HttpClientFactory", "AvailabilityStrategy", "ServerCertificateCustomValidationCallback",
            "CosmosClientTelemetryOptions", "FaultInjector", "ThroughputBucket"
        ];
        Assert.Equal(reviewed.Order(), typeof(CosmosClientOptions).GetProperties().Select(p => p.Name).Order());
    }

    [Theory]
    [InlineData(typeof(CosmosClient), typeof(ContentValidationClient))]
    [InlineData(typeof(Database), typeof(ContentValidationDatabase))]
    [InlineData(typeof(Container), typeof(ContentValidationContainer))]
    public void EverySdkVirtualEntryPointIsExplicitlyOverridden(Type sdkType, Type wrapperType)
    {
        foreach (MethodInfo method in sdkType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.IsVirtual && !m.IsFinal))
        {
            Assert.Contains(wrapperType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly),
                candidate => candidate.GetBaseDefinition() == method.GetBaseDefinition());
        }
        Assert.True(wrapperType.IsSealed);
    }

    [Fact]
    public async Task AllBlockedOverloadsRejectBeforeInnerSubmission()
    {
        using Harness h = new();
        await AssertBlockedSurface(h.Container, typeof(Container),
            ["get_Id", "get_Database", "CreateItemAsync", "ReadItemAsync", "DeleteItemAsync", "CreateItemStreamAsync", "ReadItemStreamAsync", "DeleteItemStreamAsync"]);
        await AssertBlockedSurface(h.Database, typeof(Database), ["get_Id", "get_Client", "GetContainer"]);
        await AssertBlockedSurface(h.Client, typeof(CosmosClient), ["get_Endpoint", "get_ClientOptions", "get_ResponseFactory", "ReadAccountAsync", "GetDatabase", "GetContainer", "Dispose"]);
        Assert.Equal(0, h.Inner.Calls);
    }

    private static async Task AssertBlockedSurface(object wrapper, Type sdkType, string[] permitted)
    {
        foreach (MethodInfo definition in sdkType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
        {
            if (!definition.IsVirtual || permitted.Contains(definition.Name)) continue;
            if (definition.Name == "ReadThroughputAsync" && definition.GetParameters().Length == 1) continue;
            MethodInfo method = definition.IsGenericMethodDefinition ? definition.MakeGenericMethod(typeof(JsonElement)) : definition;
            object?[] arguments = method.GetParameters().Select(p => p.ParameterType.IsValueType ? Activator.CreateInstance(p.ParameterType) : null).ToArray();
            Exception? failure = await Record.ExceptionAsync(async () =>
            {
                try
                {
                    object? result = method.Invoke(wrapper, arguments);
                    if (result is Task task) await task;
                }
                catch (TargetInvocationException ex) when (ex.InnerException is not null)
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                }
            });
            Assert.True(failure is NotSupportedException, $"{method} did not reject: {failure}");
        }
    }

    [Fact]
    public async Task TypedCreateAndReadUseSerializerWithoutStreamDelegationOrDoubleSigning()
    {
        using Harness h = new();
        JsonElement item = JsonSerializer.Deserialize<JsonElement>(Document);
        ItemResponse<JsonElement> created = await h.Container.CreateItemAsync(item, Pk);
        Assert.Equal(1, h.Inner.TypedCreates);
        Assert.Equal(0, h.Inner.StreamCreates);
        Assert.Equal(1, h.Signer.Calls);
        Assert.Equal("one", created.Resource.GetProperty("id").GetString());
        Assert.False(created.Resource.TryGetProperty("_contentValidation", out _));
        ItemResponse<JsonElement> read = await h.Container.ReadItemAsync<JsonElement>("one", Pk);
        Assert.Equal(1, h.Inner.TypedReads);
        Assert.Equal(1, h.Signer.Calls);
        Assert.Equal(7, read.Resource.GetProperty("value").GetInt32());
        Assert.False(item.TryGetProperty("_contentValidation", out _));
    }

    [Fact]
    public async Task TypedEmptySuccessFailsClosedButContentOffAndDeleteRemainAllowed()
    {
        using Harness h = new();
        h.Inner.EmptyTypedResponse = true;
        await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.ReadItemAsync<object>("one", Pk));
        await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.ReadItemAsync<JsonElement>("one", Pk));
        await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.ReadItemAsync<int>("one", Pk));
        await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.CreateItemAsync(new { id = "one", pk = "p" }, Pk));
        ItemResponse<object> off = await h.Container.CreateItemAsync<object>(new { id = "one", pk = "p" }, Pk, new ItemRequestOptions { EnableContentResponseOnWrite = false });
        Assert.Null(off.Resource);
        Assert.Equal(HttpStatusCode.NoContent, (await h.Container.DeleteItemAsync<object>("one", Pk)).StatusCode);
    }

    [Fact]
    public void PinnedRequestOptionSurfaceRequiresReviewWhenSdkAddsSettings()
    {
        string[] reviewed =
        [
            "PreTriggers", "PostTriggers", "IndexingDirective", "SessionToken", "ConsistencyLevel",
            "ReadConsistencyStrategy", "EnableContentResponseOnWrite", "DedicatedGatewayRequestOptions",
            "IfMatchEtag", "IfNoneMatchEtag", "Properties", "AddRequestHeaders", "PriorityLevel",
            "CosmosThresholdOptions", "ExcludeRegions", "AvailabilityStrategy", "ThroughputBucket"
        ];
        Assert.Equal(reviewed.Order(), typeof(ItemRequestOptions).GetProperties().Select(p => p.Name).Order());
    }

    [Fact]
    public async Task PublicOnlyProcessorRejectsWritesButAllowsReadAndDelete()
    {
        using Harness writer = new();
        using Harness reader = new(writer.Resolver, canSign: false);
        using RecyclableMemoryStream signed = writer.SignDocument();
        reader.Inner.ReadResponse = Response(HttpStatusCode.OK, reader.Processor.Buffers.Read(signed));
        using ResponseMessage read = await reader.Container.ReadItemStreamAsync("one", Pk);
        using TrackingStream input = new(Document);
        ContentValidationException typedFailure = await Assert.ThrowsAsync<ContentValidationException>(() => reader.Container.CreateItemAsync(new { id = "one", pk = "p" }, Pk));
        ContentValidationException streamFailure = await Assert.ThrowsAsync<ContentValidationException>(() => reader.Container.CreateItemStreamAsync(input, Pk));
        Assert.Equal(ContentValidationFailure.SigningUnavailable, typedFailure.Failure);
        Assert.Equal(ContentValidationFailure.SigningUnavailable, streamFailure.Failure);
        Assert.Equal(0, input.ReadCalls);
        Assert.Equal(0, reader.Inner.StreamCreates);
        using ResponseMessage deleted = await reader.Container.DeleteItemStreamAsync("one", Pk);
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await reader.Container.DeleteItemAsync<JsonElement>("one", Pk)).StatusCode);
    }

    [Fact]
    public async Task RejectsMissingPartitionKeysAndEveryStreamTypedTarget()
    {
        using Harness h = new();
        await Assert.ThrowsAsync<ArgumentException>(() => h.Container.CreateItemAsync(new { id = "one", pk = "p" }));
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.ReadItemAsync<Stream>("one", Pk));
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.ReadItemAsync<MemoryStream>("one", Pk));
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.DeleteItemAsync<Stream>("one", Pk));
        using TrackingStream stream = new(Document);
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.CreateItemAsync<object>(stream, Pk));
        Assert.Equal(0, h.Inner.Calls);
    }

    [Fact]
    public async Task HeaderHooksAreRejectedOnEveryPermittedItemOperation()
    {
        using Harness h = new();
        ItemRequestOptions[] forbidden =
        [
            new() { AddRequestHeaders = _ => throw new InvalidOperationException("Must not run") },
            new() { Properties = new Dictionary<string, object>() }, new DerivedItemOptions()
        ];
        foreach (ItemRequestOptions options in forbidden)
        {
            using TrackingStream stream = new(Document);
            await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.CreateItemAsync(new { id = "one", pk = "p" }, Pk, options));
            await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.ReadItemAsync<JsonElement>("one", Pk, options));
            await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.DeleteItemAsync<JsonElement>("one", Pk, options));
            await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.CreateItemStreamAsync(stream, Pk, options));
            await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.ReadItemStreamAsync("one", Pk, options));
            await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.DeleteItemStreamAsync("one", Pk, options));
            Assert.Equal(0, stream.ReadCalls);
        }
        Assert.Equal(0, h.Inner.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WriteTriggerExecutionIsRejectedBeforeContentReadOrSubmission(bool preTrigger)
    {
        using Harness h = new();
        ItemRequestOptions options = preTrigger
            ? new() { PreTriggers = ["server-mutation"] }
            : new() { PostTriggers = ["server-mutation"] };
        using TrackingStream source = new(Document);
        Assert.Contains("trigger", (await Assert.ThrowsAsync<NotSupportedException>(() =>
            h.Container.CreateItemAsync(new { id = "one", pk = "p" }, Pk, options))).Message);
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.CreateItemStreamAsync(source, Pk, options));
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.DeleteItemAsync<JsonElement>("one", Pk, options));
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Container.DeleteItemStreamAsync("one", Pk, options));
        Assert.Equal(0, source.ReadCalls);
        Assert.Equal(0, h.Signer.Calls);
        Assert.Equal(0, h.Inner.Calls);
    }

    [Fact]
    public async Task EmptyWriteTriggerListsAreAllowedAndSnapshottedBeforeInputIsRead()
    {
        using Harness h = new();
        List<string> preTriggers = [];
        List<string> postTriggers = [];
        ItemRequestOptions options = new() { PreTriggers = preTriggers, PostTriggers = postTriggers, EnableContentResponseOnWrite = false };
        using TrackingStream source = new(Document)
        {
            BeforeFirstRead = _ =>
            {
                preTriggers.Add("late-pre-trigger");
                postTriggers.Add("late-post-trigger");
                return Task.CompletedTask;
            }
        };
        h.Inner.CreateResponse = Response(HttpStatusCode.Created);
        using ResponseMessage response = await h.Container.CreateItemStreamAsync(source, Pk, options);
        Assert.Empty(h.Inner.LastOptions!.PreTriggers);
        Assert.Empty(h.Inner.LastOptions.PostTriggers);
        Assert.Single(preTriggers);
        Assert.Single(postTriggers);
    }

    [Fact]
    public async Task TriggerGuardIsWriteOnlyAndReadOptionsAreCopied()
    {
        using Harness h = new();
        _ = await h.Container.CreateItemAsync(new { id = "one", pk = "p" }, Pk);
        List<string> pre = ["irrelevant-to-read"];
        ItemRequestOptions options = new() { PreTriggers = pre, PostTriggers = ["also-irrelevant"] };
        _ = await h.Container.ReadItemAsync<JsonElement>("one", Pk, options);
        Assert.NotSame(pre, h.Inner.LastOptions!.PreTriggers);
        Assert.Single(h.Inner.LastOptions.PreTriggers);
        using RecyclableMemoryStream signed = h.SignDocument();
        h.Inner.ReadResponse = Response(HttpStatusCode.OK, h.Processor.Buffers.Read(signed));
        using ResponseMessage response = await h.Container.ReadItemStreamAsync("one", Pk, options);
        Assert.NotSame(pre, h.Inner.LastOptions!.PreTriggers);
    }

    [Fact]
    public async Task EveryStoredProcedureExecutionOverloadIsRejectedAtContainerBoundary()
    {
        using Harness h = new();
        using TrackingStream arguments = new("[]");
        NotSupportedException error = await Assert.ThrowsAsync<NotSupportedException>(() =>
            h.Container.Scripts.ExecuteStoredProcedureAsync<JsonElement>("procedure", Pk, Array.Empty<object>()));
        Assert.Contains("Stored-procedure", error.Message);
        await Assert.ThrowsAsync<NotSupportedException>(() =>
            h.Container.Scripts.ExecuteStoredProcedureStreamAsync("procedure", Pk, Array.Empty<object>()));
        await Assert.ThrowsAsync<NotSupportedException>(() =>
            h.Container.Scripts.ExecuteStoredProcedureStreamAsync("procedure", arguments, Pk));
        Assert.Equal(0, arguments.ReadCalls);
        Assert.Equal(0, h.Inner.Calls);
    }

    [Fact]
    public async Task RequestOptionsAreSnapshottedBeforeAwaitingCallerInput()
    {
        using Harness h = new();
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using TrackingStream source = new(Document)
        {
            BeforeFirstRead = async token => { entered.SetResult(); await release.Task.WaitAsync(token); }
        };
        ItemRequestOptions options = new()
        {
            IfMatchEtag = "etag", SessionToken = "session", EnableContentResponseOnWrite = false,
            ExcludeRegions = [Regions.EastUS],
            DedicatedGatewayRequestOptions = new() { BypassIntegratedCache = true },
            CosmosThresholdOptions = new() { PointOperationLatencyThreshold = TimeSpan.FromSeconds(8) }
        };
        h.Inner.CreateResponse = Response(HttpStatusCode.Created);
        Task<ResponseMessage> pending = h.Container.CreateItemStreamAsync(source, Pk, options);
        await entered.Task;
        options.PreTriggers = ["late-trigger"];
        options.Properties = new Dictionary<string, object> { ["late"] = true };
        options.AddRequestHeaders = _ => throw new InvalidOperationException("Must not run");
        options.EnableContentResponseOnWrite = true;
        options.ExcludeRegions.Add(Regions.WestUS);
        options.DedicatedGatewayRequestOptions.BypassIntegratedCache = false;
        options.CosmosThresholdOptions.PointOperationLatencyThreshold = TimeSpan.FromSeconds(99);
        release.SetResult();
        using ResponseMessage response = await pending;
        ItemRequestOptions snapshot = Assert.IsType<ItemRequestOptions>(h.Inner.LastOptions);
        Assert.NotSame(options, snapshot);
        Assert.Null(snapshot.PreTriggers);
        Assert.Null(snapshot.Properties);
        Assert.Null(snapshot.AddRequestHeaders);
        Assert.False(snapshot.EnableContentResponseOnWrite);
        Assert.Single(snapshot.ExcludeRegions);
        Assert.True(snapshot.DedicatedGatewayRequestOptions.BypassIntegratedCache);
        Assert.Equal(TimeSpan.FromSeconds(8), snapshot.CosmosThresholdOptions.PointOperationLatencyThreshold);
        Assert.Equal("etag", snapshot.IfMatchEtag);
        Assert.Equal("session", snapshot.SessionToken);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StreamCreateSignsOnceAndKeepsReplayableOutputAliveThroughRetry(bool seekable)
    {
        using Harness h = new();
        using TrackingStream source = new("prefix" + Document, seekable);
        source.SetInitialPosition(6);
        RecyclableMemoryStream? outbound = null;
        h.Inner.OnStreamCreate = async (body, _, token) =>
        {
            outbound = Assert.IsType<RecyclableMemoryStream>(body);
            Assert.True(body.CanSeek);
            Assert.Equal(0, body.Position);
            h.Processor.Validate(outbound.GetReadOnlySequence());
            using RecyclableMemoryStream firstAttempt = await h.Processor.Buffers.ReadAsync(body, token);
            body.Position = body.Length;
            await Task.Yield();
            Assert.True(body.CanRead);
            body.Position = 0;
            using RecyclableMemoryStream retry = await h.Processor.Buffers.ReadAsync(body, token);
            Assert.Equal(firstAttempt.Length, retry.Length);
            h.Processor.Validate(retry.GetReadOnlySequence());
            return Response(HttpStatusCode.Created, h.Processor.Buffers.Read(body));
        };
        ResponseMessage response = await h.Container.CreateItemStreamAsync(source, Pk);
        Assert.Equal(1, h.Signer.Calls);
        Assert.Equal(0, source.DisposeCalls);
        if (seekable) Assert.Equal(6, source.Position);
        Assert.False(outbound!.CanRead);
        RecyclableMemoryStream returned = Assert.IsType<RecyclableMemoryStream>(response.Content);
        Assert.True(returned.CanRead);
        Assert.Equal(0, returned.Position);
        h.Processor.Validate(returned.GetReadOnlySequence());
        Assert.True(h.Processor.Buffers.InUseBytes > 0);
        response.Dispose();
        Assert.False(returned.CanRead);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task StreamCreateCanResignRecognizedEnvelope()
    {
        using Harness h = new();
        using RecyclableMemoryStream original = h.SignDocument();
        h.Inner.CreateResponse = Response(HttpStatusCode.Created);
        using ResponseMessage response = await h.Container.CreateItemStreamAsync(original, Pk, new ItemRequestOptions { EnableContentResponseOnWrite = false });
        Assert.Equal(2, h.Signer.Calls);
        Assert.Equal(0, original.Position);
        Assert.True(original.CanRead);
    }

    [Fact]
    public async Task SuccessfulReadReplacesBodyAndPreservesResponseIdentityAndHeaders()
    {
        using Harness h = new();
        using RecyclableMemoryStream signed = h.SignDocument();
        using JsonDocument json = JsonDocument.Parse(signed);
        TrackingStream original = new(json.RootElement.GetRawText());
        TrackingResponse response = Response(HttpStatusCode.OK, original);
        response.Headers.Add("x-ms-activity-id", "activity");
        response.Headers.Add("etag", "etag");
        h.Inner.ReadResponse = response;
        ResponseMessage returned = await h.Container.ReadItemStreamAsync("one", Pk);
        Assert.Same(response, returned);
        Assert.Equal("activity", returned.Headers.ActivityId);
        Assert.Equal("etag", returned.Headers.ETag);
        Assert.Equal(1, original.DisposeCalls);
        Assert.Equal(0, returned.Content.Position);
        RecyclableMemoryStream body = Assert.IsType<RecyclableMemoryStream>(returned.Content);
        h.Processor.Validate(body.GetReadOnlySequence());
        returned.Dispose();
        Assert.Equal(1, response.DisposeCalls);
        Assert.False(body.CanRead);
    }

    [Fact]
    public async Task SegmentedResponseKeepsExactSignedBytesAndLogicalLength()
    {
        using Harness h = new();
        string document = JsonSerializer.Serialize(new { id = "one", pk = "p", data = new string('x', 100_000) });
        using RecyclableMemoryStream signed = h.Processor.Sign(new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(document)));
        RecyclableMemoryStream original = h.Processor.Buffers.Read(signed);
        h.Inner.ReadResponse = Response(HttpStatusCode.OK, original);
        using ResponseMessage response = await h.Container.ReadItemStreamAsync("one", Pk);
        RecyclableMemoryStream returned = Assert.IsType<RecyclableMemoryStream>(response.Content);
        Assert.False(original.CanRead);
        Assert.Equal(signed.Length, returned.Length);
        Assert.Equal(0, returned.Position);
        AssertSequencesEqual(signed.GetReadOnlySequence(), returned.GetReadOnlySequence());
    }

    private static void AssertSequencesEqual(ReadOnlySequence<byte> expected, ReadOnlySequence<byte> actual)
    {
        Assert.Equal(expected.Length, actual.Length);
        SequenceReader<byte> left = new(expected);
        SequenceReader<byte> right = new(actual);
        while (left.TryRead(out byte value))
        {
            Assert.True(right.TryRead(out byte other));
            Assert.Equal(value, other);
        }
        Assert.True(right.End);
    }

    [Theory]
    [InlineData(404)]
    [InlineData(429)]
    [InlineData(304)]
    public async Task ServiceErrorsAndNotModifiedAreReturnedUntouched(int status)
    {
        using Harness h = new();
        TrackingStream body = new("not a signed document");
        TrackingResponse response = Response((HttpStatusCode)status, body);
        response.Headers.Add("x-ms-activity-id", "preserved");
        h.Inner.ReadResponse = response;
        using ResponseMessage returned = await h.Container.ReadItemStreamAsync("one", Pk);
        Assert.Same(response, returned);
        Assert.Same(body, returned.Content);
        Assert.Equal("preserved", returned.Headers.ActivityId);
        Assert.Equal(0, body.ReadCalls);
        Assert.Equal(0, body.Position);
        Assert.Equal(0, body.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task CreateErrorIsNotParsedAndDeleteDoesNotParseEvenNonemptyBody()
    {
        using Harness h = new();
        using TrackingStream source = new(Document);
        TrackingStream conflict = new("service error");
        h.Inner.CreateResponse = Response(HttpStatusCode.Conflict, conflict);
        using ResponseMessage create = await h.Container.CreateItemStreamAsync(source, Pk);
        Assert.Same(h.Inner.CreateResponse, create);
        Assert.Equal(0, conflict.ReadCalls);
        TrackingStream cleanup = new("not a document");
        h.Inner.DeleteResponse = Response(HttpStatusCode.NoContent, cleanup);
        using ResponseMessage delete = await h.Container.DeleteItemStreamAsync("one", Pk);
        Assert.Same(h.Inner.DeleteResponse, delete);
        Assert.Equal(0, cleanup.ReadCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task InvalidCreateResponseFailsAfterSubmitAndReleasesAllOwnedBuffers()
    {
        using Harness h = new();
        using TrackingStream source = new(Document);
        TrackingStream body = new(Document);
        TrackingResponse response = Response(HttpStatusCode.Created, body);
        h.Inner.CreateResponse = response;
        await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.CreateItemStreamAsync(source, Pk));
        Assert.Equal(1, h.Inner.StreamCreates);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, body.DisposeCalls);
        Assert.Equal(0, source.DisposeCalls);
        Assert.Equal(0, source.Position);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(Document)]
    [InlineData("{invalid")]
    public async Task InvalidSuccessfulReadsDisposeResponseAndAllLeases(string? content)
    {
        using Harness h = new();
        TrackingStream? body = content is null ? null : new TrackingStream(content);
        TrackingResponse response = Response(HttpStatusCode.OK, body);
        h.Inner.ReadResponse = response;
        await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.ReadItemStreamAsync("one", Pk));
        Assert.Equal(1, response.DisposeCalls);
        if (body is not null) Assert.Equal(1, body.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task EmptySuccessfulReadIsNotAcceptedEvenFor204()
    {
        using Harness h = new();
        h.Inner.ReadResponse = Response(HttpStatusCode.NoContent);
        await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.ReadItemStreamAsync("one", Pk));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task EmptyCreateRequiresContentOffAndHonorsClientDefault(string? content)
    {
        using Harness h = new();
        using TrackingStream source = new(Document);
        h.Inner.CreateResponse = Response(HttpStatusCode.Created, content is null ? null : new TrackingStream(content));
        ContentValidationException required = await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.CreateItemStreamAsync(source, Pk));
        Assert.Equal(ContentValidationFailure.MissingSignature, required.Failure);
        h.Inner.CreateResponse = Response(HttpStatusCode.Created, content is null ? null : new TrackingStream(content));
        using ResponseMessage off = await h.Container.CreateItemStreamAsync(source, Pk, new ItemRequestOptions { EnableContentResponseOnWrite = false });
        ContentValidationContainer defaultOff = new(h.Database, h.Inner, h.Processor, contentResponseOnWrite: false);
        h.Inner.CreateResponse = Response(HttpStatusCode.Created, content is null ? null : new TrackingStream(content));
        using ResponseMessage inherited = await defaultOff.CreateItemStreamAsync(source, Pk);
        h.Inner.CreateResponse = Response(HttpStatusCode.Created, content is null ? null : new TrackingStream(content));
        ContentValidationException overridden = await Assert.ThrowsAsync<ContentValidationException>(() => defaultOff.CreateItemStreamAsync(source, Pk, new ItemRequestOptions { EnableContentResponseOnWrite = true }));
        Assert.Equal(ContentValidationFailure.MissingSignature, overridden.Failure);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task ContentOffStillValidatesAndTransfersNonemptyWriteResponse(bool perRequest, bool seekable)
    {
        using Harness h = new(contentResponseOnWrite: perRequest);
        using TrackingStream source = new("prefix" + Document);
        source.Position = 6;
        string content = h.SignedDocumentText();
        TrackingStream original = new(content, seekable);
        TrackingResponse response = Response(HttpStatusCode.Created, original);
        response.Headers.Add("x-ms-activity-id", "preserved");
        response.Headers.Add("etag", "etag");
        h.Inner.CreateResponse = response;
        ItemRequestOptions? options = perRequest ? new() { EnableContentResponseOnWrite = false } : null;

        ResponseMessage returned = await h.Container.CreateItemStreamAsync(source, Pk, options);
        Assert.Same(response, returned);
        Assert.Equal("preserved", returned.Headers.ActivityId);
        Assert.Equal("etag", returned.Headers.ETag);
        Assert.Equal(0, response.DisposeCalls);
        Assert.Equal(1, original.DisposeCalls);
        Assert.True(original.ReadCalls > 0);
        RecyclableMemoryStream body = Assert.IsType<RecyclableMemoryStream>(returned.Content);
        Assert.Equal(0, body.Position);
        AssertSequencesEqual(new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(content)), body.GetReadOnlySequence());
        h.Processor.Validate(body.GetReadOnlySequence());
        Assert.True(h.Processor.Buffers.InUseBytes > 0);
        Assert.Equal(6, source.Position);
        Assert.Equal(0, source.DisposeCalls);

        returned.Dispose();
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(1, original.DisposeCalls);
        Assert.False(body.CanRead);
        Assert.True(source.CanRead);
        Assert.Equal(0, source.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(true, "unsigned", ContentValidationFailure.MissingSignature)]
    [InlineData(false, "unsigned", ContentValidationFailure.MissingSignature)]
    [InlineData(true, "removed-signature", ContentValidationFailure.MissingSignature)]
    [InlineData(false, "removed-signature", ContentValidationFailure.MissingSignature)]
    [InlineData(true, "tampered", ContentValidationFailure.InvalidSignature)]
    [InlineData(false, "tampered", ContentValidationFailure.InvalidSignature)]
    [InlineData(true, "oversized", ContentValidationFailure.PayloadTooLarge)]
    [InlineData(false, "oversized", ContentValidationFailure.PayloadTooLarge)]
    public async Task ContentOffRejectsInvalidNonemptyWriteResponseAndReleasesLeases(bool perRequest, string kind, ContentValidationFailure expected)
    {
        using Harness h = new(contentResponseOnWrite: perRequest);
        using TrackingStream source = new("prefix" + Document);
        source.Position = 6;
        string content;
        switch (kind)
        {
            case "unsigned":
                content = Document;
                break;
            case "oversized":
                content = new string('x', h.Processor.MaxDocumentBytes + 1);
                break;
            default:
                JsonObject document = JsonNode.Parse(h.SignedDocumentText())!.AsObject();
                if (kind == "removed-signature") Assert.True(document.Remove("_contentValidation"));
                else document["value"] = 8;
                content = document.ToJsonString();
                break;
        }
        TrackingStream original = new(content, seekable: false);
        TrackingResponse response = Response(HttpStatusCode.Created, original);
        h.Inner.CreateResponse = response;
        ItemRequestOptions? options = perRequest ? new() { EnableContentResponseOnWrite = false } : null;

        ContentValidationException failure = await Assert.ThrowsAsync<ContentValidationException>(() =>
            h.Container.CreateItemStreamAsync(source, Pk, options));
        Assert.Equal(expected, failure.Failure);
        Assert.Equal(1, h.Inner.StreamCreates);
        Assert.True(original.ReadCalls > 0);
        Assert.Equal(1, original.DisposeCalls);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(6, source.Position);
        Assert.Equal(0, source.DisposeCalls);
        Assert.True(source.CanRead);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(true, null, true)]
    [InlineData(false, null, true)]
    [InlineData(true, "", true)]
    [InlineData(false, "", true)]
    [InlineData(true, "", false)]
    [InlineData(false, "", false)]
    public async Task ContentOffAllowsNullOrEmptyWriteResponseWithoutChangingOwnership(bool perRequest, string? content, bool seekable)
    {
        using Harness h = new(contentResponseOnWrite: perRequest);
        using TrackingStream source = new("prefix" + Document);
        source.Position = 6;
        TrackingStream? original = content is null ? null : new TrackingStream(content, seekable);
        TrackingResponse response = Response(HttpStatusCode.Created, original);
        response.Headers.Add("x-ms-activity-id", "preserved");
        h.Inner.CreateResponse = response;
        ItemRequestOptions? options = perRequest ? new() { EnableContentResponseOnWrite = false } : null;

        ResponseMessage returned = await h.Container.CreateItemStreamAsync(source, Pk, options);
        Assert.Same(response, returned);
        Assert.Same(original, returned.Content);
        Assert.Equal("preserved", returned.Headers.ActivityId);
        Assert.Equal(0, response.DisposeCalls);
        if (original is not null)
        {
            Assert.True(original.ReadCalls > 0);
            Assert.Equal(0, original.Position);
            Assert.Equal(0, original.DisposeCalls);
        }
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
        returned.Dispose();
        Assert.Equal(1, response.DisposeCalls);
        if (original is not null) Assert.Equal(1, original.DisposeCalls);
        Assert.Equal(6, source.Position);
        Assert.Equal(0, source.DisposeCalls);
        Assert.True(source.CanRead);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(true, 404)]
    [InlineData(false, 404)]
    [InlineData(true, 429)]
    [InlineData(false, 429)]
    [InlineData(true, 304)]
    [InlineData(false, 304)]
    public async Task ContentOffLeavesWriteServiceErrorsAndNotModifiedUntouched(bool perRequest, int status)
    {
        using Harness h = new(contentResponseOnWrite: perRequest);
        using TrackingStream source = new(Document);
        TrackingStream original = new("not a document");
        TrackingResponse response = Response((HttpStatusCode)status, original);
        response.Headers.Add("x-ms-activity-id", "preserved");
        h.Inner.CreateResponse = response;
        ItemRequestOptions? options = perRequest ? new() { EnableContentResponseOnWrite = false } : null;

        ResponseMessage returned = await h.Container.CreateItemStreamAsync(source, Pk, options);
        Assert.Same(response, returned);
        Assert.Same(original, returned.Content);
        Assert.Equal("preserved", returned.Headers.ActivityId);
        Assert.Equal(0, original.ReadCalls);
        Assert.Equal(0, original.Position);
        Assert.Equal(0, original.DisposeCalls);
        Assert.Equal(0, response.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
        returned.Dispose();
        Assert.Equal(1, original.DisposeCalls);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(0, source.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task PreCancelledOperationsNeverSubmitOrReadSource()
    {
        using Harness h = new();
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        using TrackingStream source = new(Document);
        CancellationToken token = cancellation.Token;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.CreateItemStreamAsync(source, Pk, cancellationToken: token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.ReadItemStreamAsync("one", Pk, cancellationToken: token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.DeleteItemStreamAsync("one", Pk, cancellationToken: token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.CreateItemAsync(new { id = "one", pk = "p" }, Pk, cancellationToken: token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.ReadItemAsync<JsonElement>("one", Pk, cancellationToken: token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.DeleteItemAsync<JsonElement>("one", Pk, cancellationToken: token));
        Assert.Equal(0, source.ReadCalls);
        Assert.Equal(0, h.Inner.Calls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task CancellationDuringCopyRestoresInputAndNeverSubmits()
    {
        using Harness h = new();
        using CancellationTokenSource cancellation = new();
        using TrackingStream source = new("prefix" + Document)
        {
            BeforeFirstRead = _ => { cancellation.Cancel(); return Task.CompletedTask; }
        };
        source.Position = 6;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.CreateItemStreamAsync(source, Pk, cancellationToken: cancellation.Token));
        Assert.Equal(6, source.Position);
        Assert.Equal(0, source.DisposeCalls);
        Assert.Equal(0, h.Inner.Calls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task CancellationAfterSigningAndSdkFailureReleaseAllWriteLeases()
    {
        using Harness h = new();
        using CancellationTokenSource cancellation = new();
        using TrackingStream source = new(Document);
        h.Signer.AfterSign = cancellation.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.CreateItemStreamAsync(source, Pk, cancellationToken: cancellation.Token));
        Assert.Equal(0, h.Inner.Calls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
        h.Signer.AfterSign = null;
        Stream? sent = null;
        h.Inner.OnStreamCreate = (body, _, _) =>
        {
            sent = body;
            throw new IOException("transport failed");
        };
        await Assert.ThrowsAsync<IOException>(() => h.Container.CreateItemStreamAsync(source, Pk));
        Assert.False(sent!.CanRead);
        Assert.Equal(0, source.Position);
        Assert.Equal(0, source.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task CancelledSuccessfulResponseDisposesBodyAndResponse()
    {
        using Harness h = new();
        using CancellationTokenSource cancellation = new();
        TrackingStream body = new(Document)
        {
            BeforeFirstRead = _ => { cancellation.Cancel(); return Task.CompletedTask; }
        };
        TrackingResponse response = Response(HttpStatusCode.OK, body);
        h.Inner.ReadResponse = response;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Container.ReadItemStreamAsync("one", Pk, cancellationToken: cancellation.Token));
        Assert.Equal(1, body.DisposeCalls);
        Assert.Equal(1, response.DisposeCalls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task OversizedInputIsRejectedBeforeSubmitAndPositionIsRestored()
    {
        using Harness h = new();
        using TrackingStream source = new(new string('x', h.Processor.MaxDocumentBytes + 1));
        ContentValidationException error = await Assert.ThrowsAsync<ContentValidationException>(() => h.Container.CreateItemStreamAsync(source, Pk));
        Assert.Equal(ContentValidationFailure.PayloadTooLarge, error.Failure);
        Assert.Equal(0, source.Position);
        Assert.Equal(0, h.Inner.Calls);
        Assert.Equal(0, h.Processor.Buffers.InUseBytes);
    }

    private static TrackingResponse Response(HttpStatusCode code, Stream? body = null) => new(code) { Content = body! };

    private sealed class Harness : IDisposable
    {
        private readonly UnsafeEcdsaContentSigner signer;
        private readonly UnsafeEcdsaContentVerifier verifier;
        public CountingSigner Signer { get; }
        public IVerificationKeyResolver Resolver { get; }
        public ContentValidationProcessor Processor { get; }
        public ContentValidationClient Client { get; }
        public ContentValidationDatabase Database { get; }
        public ContentValidationContainer Container { get; }
        public FakeContainer Inner { get; }

        public Harness(IVerificationKeyResolver? resolver = null, bool canSign = true, bool contentResponseOnWrite = true)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            signer = new UnsafeEcdsaContentSigner("wrapper-test", key.ExportPkcs8PrivateKeyPem());
            verifier = new UnsafeEcdsaContentVerifier("wrapper-test", key.ExportSubjectPublicKeyInfoPem());
            Signer = new CountingSigner(signer);
            Resolver = resolver ?? new UnsafeInMemoryVerificationKeyResolver([verifier]);
            Processor = UnsafeSampleProviders.CreateProcessor(new ContentValidationOptions(), Resolver, canSign ? Signer : null);
            ContentValidationSerializer serializer = new(Processor, new PlainSerializer());
            // This test-only constructor supplies a real SDK client for inert navigation, never transport.
            Client = new ContentValidationClient(new CosmosClient(Endpoint, Key,
                new CosmosClientOptions { Serializer = serializer, EnableContentResponseOnWrite = contentResponseOnWrite }),
                Processor, new CosmosClientOptions { EnableContentResponseOnWrite = contentResponseOnWrite });
            Database = (ContentValidationDatabase)Client.GetDatabase("db");
            Inner = new FakeContainer(serializer, Processor);
            Container = new ContentValidationContainer(Database, Inner, Processor, contentResponseOnWrite);
        }

        public RecyclableMemoryStream SignDocument() => Processor.Sign(new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(Document)));

        public string SignedDocumentText()
        {
            using RecyclableMemoryStream signed = SignDocument();
            using JsonDocument document = JsonDocument.Parse(signed);
            return document.RootElement.GetRawText();
        }

        public void Dispose()
        {
            Inner.Dispose();
            Client.Dispose();
            signer.Dispose();
            verifier.Dispose();
        }
    }

    private sealed class CountingSigner(IContentSigner inner) : IContentSigner
    {
        public int Calls { get; private set; }
        public Action? AfterSign { get; set; }
        public string KeyId => inner.KeyId;
        public string AlgorithmId => inner.AlgorithmId;
        public byte[] SignHash(ReadOnlySpan<byte> hash)
        {
            Calls++;
            byte[] result = inner.SignHash(hash);
            AfterSign?.Invoke();
            return result;
        }
    }

    private sealed class OfflineCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Offline test must not request tokens.");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Offline test must not request tokens.");
    }

    private sealed class DerivedClientOptions : CosmosClientOptions;
    private sealed class DerivedItemOptions : ItemRequestOptions;
    private sealed class PassThroughHandler : RequestHandler;

    private sealed class FakeClient : CosmosClient
    {
        public int DisposeCalls { get; private set; }
        protected override void Dispose(bool disposing) { if (disposing) DisposeCalls++; }
    }

    private sealed class PlainSerializer : CosmosSerializer
    {
        public override T FromStream<T>(Stream stream)
        {
            using (stream) return JsonSerializer.Deserialize<T>(stream)!;
        }
        public override Stream ToStream<T>(T input)
        {
            MemoryStream stream = new();
            JsonSerializer.Serialize(stream, input);
            stream.Position = 0;
            return stream;
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

    private sealed class TrackingStream(string content, bool seekable = true) : MemoryStream(Encoding.UTF8.GetBytes(content))
    {
        public int ReadCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public Func<CancellationToken, Task>? BeforeFirstRead { get; init; }
        public override bool CanSeek => seekable && base.CanSeek;
        public void SetInitialPosition(long position) => base.Position = position;
        public override byte[] ToArray() => throw new InvalidOperationException("Do not flatten test content.");
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ReadCalls++;
            if (ReadCalls == 1 && BeforeFirstRead is not null) await BeforeFirstRead(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return await base.ReadAsync(buffer[..Math.Min(buffer.Length, 113)], cancellationToken);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeCalls++;
            base.Dispose(disposing);
        }
    }

    private sealed class FakeItemResponse<T>(T resource, HttpStatusCode status) : ItemResponse<T>
    {
        public override T Resource => resource;
        public override HttpStatusCode StatusCode => status;
    }

    // A handwritten SDK fake: all non-point calls count and fail. No SDK internals or mocking package.
    private sealed class FakeContainer(CosmosSerializer serializer, ContentValidationProcessor processor) : Container, IDisposable
    {
        private RecyclableMemoryStream? stored;
        public int Calls { get; private set; }
        public int TypedCreates { get; private set; }
        public int TypedReads { get; private set; }
        public int StreamCreates { get; private set; }
        public bool EmptyTypedResponse { get; set; }
        public ItemRequestOptions? LastOptions { get; private set; }
        public ResponseMessage? ReadResponse { get; set; }
        public ResponseMessage? CreateResponse { get; set; }
        public ResponseMessage? DeleteResponse { get; set; }
        public Func<Stream, ItemRequestOptions?, CancellationToken, Task<ResponseMessage>>? OnStreamCreate { get; set; }
        public override string Id => "items";
        public override Database Database => throw Unexpected();
        public override Conflicts Conflicts => throw Unexpected();
        public override Scripts Scripts => throw Unexpected();

        public override Task<ItemResponse<T>> CreateItemAsync<T>(T item, PartitionKey? partitionKey = null, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
        {
            Calls++; TypedCreates++; LastOptions = requestOptions;
            if (EmptyTypedResponse) return Task.FromResult<ItemResponse<T>>(new FakeItemResponse<T>(default!, HttpStatusCode.Created));
            using Stream wire = serializer.ToStream(item);
            stored?.Dispose();
            stored = processor.Buffers.Read(wire);
            ItemResponse<T> response = new FakeItemResponse<T>(serializer.FromStream<T>(processor.Buffers.Read(stored)), HttpStatusCode.Created);
            return Task.FromResult(response);
        }

        public override Task<ItemResponse<T>> ReadItemAsync<T>(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
        {
            Calls++; TypedReads++; LastOptions = requestOptions;
            if (EmptyTypedResponse) return Task.FromResult<ItemResponse<T>>(new FakeItemResponse<T>(default!, HttpStatusCode.OK));
            ItemResponse<T> response = new FakeItemResponse<T>(serializer.FromStream<T>(processor.Buffers.Read(stored!)), HttpStatusCode.OK);
            return Task.FromResult(response);
        }

        public override Task<ResponseMessage> CreateItemStreamAsync(Stream streamPayload, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
        {
            Calls++; StreamCreates++; LastOptions = requestOptions;
            return OnStreamCreate is not null ? OnStreamCreate(streamPayload, requestOptions, cancellationToken)
                : Task.FromResult(CreateResponse ?? Response(HttpStatusCode.Created, processor.Buffers.Read(streamPayload)));
        }

        public override Task<ResponseMessage> ReadItemStreamAsync(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
        {
            Calls++; LastOptions = requestOptions;
            return Task.FromResult(ReadResponse ?? Response(HttpStatusCode.NotFound));
        }

        public override Task<ResponseMessage> DeleteItemStreamAsync(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
        {
            Calls++; LastOptions = requestOptions;
            return Task.FromResult(DeleteResponse ?? Response(HttpStatusCode.NoContent));
        }

        public override Task<ItemResponse<T>> DeleteItemAsync<T>(string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
        {
            Calls++; LastOptions = requestOptions;
            return Task.FromResult<ItemResponse<T>>(new FakeItemResponse<T>(default!, HttpStatusCode.NoContent));
        }

        public void Dispose() => stored?.Dispose();
        private Exception Unexpected() { Calls++; return new InvalidOperationException("Guard allowed an unsupported inner call."); }
        public override Task<ContainerResponse> ReadContainerAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ResponseMessage> ReadContainerStreamAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ContainerResponse> ReplaceContainerAsync(ContainerProperties containerProperties, ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ResponseMessage> ReplaceContainerStreamAsync(ContainerProperties containerProperties, ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ContainerResponse> DeleteContainerAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ResponseMessage> DeleteContainerStreamAsync(ContainerRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<int?> ReadThroughputAsync(CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ThroughputResponse> ReadThroughputAsync(RequestOptions requestOptions, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ThroughputResponse> ReplaceThroughputAsync(int throughput, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ThroughputResponse> ReplaceThroughputAsync(ThroughputProperties throughputProperties, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ItemResponse<T>> UpsertItemAsync<T>(T item, PartitionKey? partitionKey = null, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ResponseMessage> UpsertItemStreamAsync(Stream streamPayload, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ItemResponse<T>> ReplaceItemAsync<T>(T item, string id, PartitionKey? partitionKey = null, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ResponseMessage> ReplaceItemStreamAsync(Stream streamPayload, string id, PartitionKey partitionKey, ItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ItemResponse<T>> PatchItemAsync<T>(string id, PartitionKey partitionKey, IReadOnlyList<PatchOperation> patchOperations, PatchItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ResponseMessage> PatchItemStreamAsync(string id, PartitionKey partitionKey, IReadOnlyList<PatchOperation> patchOperations, PatchItemRequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<FeedResponse<T>> ReadManyItemsAsync<T>(IReadOnlyList<(string, PartitionKey)> items, ReadManyRequestOptions? readManyRequestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override Task<ResponseMessage> ReadManyItemsStreamAsync(IReadOnlyList<(string, PartitionKey)> items, ReadManyRequestOptions? readManyRequestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override FeedIterator<T> GetItemQueryIterator<T>(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unexpected();
        public override FeedIterator<T> GetItemQueryIterator<T>(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unexpected();
        public override FeedIterator<T> GetItemQueryIterator<T>(FeedRange feedRange, QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unexpected();
        public override FeedIterator GetItemQueryStreamIterator(QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unexpected();
        public override FeedIterator GetItemQueryStreamIterator(string? queryText = null, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unexpected();
        public override FeedIterator GetItemQueryStreamIterator(FeedRange feedRange, QueryDefinition queryDefinition, string? continuationToken = null, QueryRequestOptions? requestOptions = null) => throw Unexpected();
        public override IOrderedQueryable<T> GetItemLinqQueryable<T>(bool allowSynchronousQueryExecution = false, string? continuationToken = null, QueryRequestOptions? requestOptions = null, CosmosLinqSerializerOptions? linqSerializerOptions = null) => throw Unexpected();
        public override TransactionalBatch CreateTransactionalBatch(PartitionKey partitionKey) => throw Unexpected();
        public override Task<IReadOnlyList<FeedRange>> GetFeedRangesAsync(CancellationToken cancellationToken = default) => throw Unexpected();
        public override FeedIterator<T> GetChangeFeedIterator<T>(ChangeFeedStartFrom changeFeedStartFrom, ChangeFeedMode changeFeedMode, ChangeFeedRequestOptions? changeFeedRequestOptions = null) => throw Unexpected();
        public override FeedIterator GetChangeFeedStreamIterator(ChangeFeedStartFrom changeFeedStartFrom, ChangeFeedMode changeFeedMode, ChangeFeedRequestOptions? changeFeedRequestOptions = null) => throw Unexpected();
        public override ChangeFeedEstimator GetChangeFeedEstimator(string processorName, Container leaseContainer) => throw Unexpected();
        public override ChangeFeedProcessorBuilder GetChangeFeedEstimatorBuilder(string processorName, ChangesEstimationHandler estimationDelegate, TimeSpan? estimationPeriod = null) => throw Unexpected();
        public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilder<T>(string processorName, ChangesHandler<T> onChangesDelegate) => throw Unexpected();
        public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilder<T>(string processorName, ChangeFeedHandler<T> onChangesDelegate) => throw Unexpected();
        public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilder(string processorName, ChangeFeedStreamHandler onChangesDelegate) => throw Unexpected();
        public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilderWithManualCheckpoint<T>(string processorName, ChangeFeedHandlerWithManualCheckpoint<T> onChangesDelegate) => throw Unexpected();
        public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilderWithManualCheckpoint(string processorName, ChangeFeedStreamHandlerWithManualCheckpoint onChangesDelegate) => throw Unexpected();
        public override Task<ResponseMessage> DeleteAllItemsByPartitionKeyStreamAsync(PartitionKey partitionKey, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => throw Unexpected();
        public override ChangeFeedProcessorBuilder GetChangeFeedProcessorBuilderWithAllVersionsAndDeletes<T>(string processorName, ChangeFeedHandler<ChangeFeedItem<T>> onChangesDelegate) => throw Unexpected();
    }
}