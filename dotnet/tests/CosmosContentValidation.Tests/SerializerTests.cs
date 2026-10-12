using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CosmosContentValidation.Sample;
using CosmosContentValidation.Sample.Providers;
using Microsoft.Azure.Cosmos;
using Microsoft.IO;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class SerializerTests
{
    private const string Envelope = "_contentValidation";
    private const string Document = "{\"id\":\"one\",\"pk\":\"tenant\",\"displayName\":\"First item\",\"value\":7}";

    [Fact]
    public void ArgumentsRejectNullProcessorNullInputStreamAndStackedProtection()
    {
        using Harness h = new();
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        Assert.Throws<ArgumentNullException>(() => new ContentValidationSerializer(null!));
        Assert.Throws<ArgumentException>(() => new ContentValidationSerializer(h.Processor, serializer));
        Assert.Throws<ArgumentNullException>(() => serializer.FromStream<Item>(null!));
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void DefaultToStreamUsesCamelCaseSignsWithoutMutatingAndReturnsAnOwnedRewoundStream()
    {
        using Harness h = new();
        Item item = new() { Id = "one", Pk = "tenant", DisplayName = "First item", Value = 7 };
        string snapshot = JsonSerializer.Serialize(item);
        RecyclableMemoryStream output = Assert.IsType<RecyclableMemoryStream>(h.Serializer.ToStream(item));
        using (output)
        {
            Assert.Equal(snapshot, JsonSerializer.Serialize(item));
            Assert.Equal(0L, output.Position);
            Assert.True(output.CanRead);
            Assert.True(output.CanSeek);
            Assert.True(h.Processor.Buffers.InUseBytes > 0);
            using JsonDocument document = JsonDocument.Parse(output.GetReadOnlySequence());
            Assert.Equal("one", document.RootElement.GetProperty("id").GetString());
            Assert.Equal("First item", document.RootElement.GetProperty("displayName").GetString());
            Assert.False(document.RootElement.TryGetProperty("Id", out _));
            Assert.False(document.RootElement.TryGetProperty("DisplayName", out _));
            Assert.Equal(JsonValueKind.Object, document.RootElement.GetProperty(Envelope).ValueKind);
            item.DisplayName = "changed after serialization";
            h.Processor.Validate(output.GetReadOnlySequence());
            Assert.Equal(0L, output.Position);
        }
        Assert.False(output.CanRead);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void DefaultMapperStripsOnlyRootEnvelopeAndDoesNotAddItToTheInputObject()
    {
        using Harness h = new();
        JsonObject input = JsonNode.Parse(Document)!.AsObject();
        input["unknown"] = JsonNode.Parse("{\"values\":[1,true,null]}");
        input["nested"] = new JsonObject { [Envelope] = "application data" };
        string snapshot = input.ToJsonString();
        Stream signed = h.Serializer.ToStream(input);
        Assert.Equal(snapshot, input.ToJsonString());
        Assert.False(input.ContainsKey(Envelope));

        Dictionary<string, JsonElement> mapped = h.Serializer.FromStream<Dictionary<string, JsonElement>>(signed);

        Assert.False(signed.CanRead);
        Assert.False(mapped.ContainsKey(Envelope));
        Assert.Equal("application data", mapped["nested"].GetProperty(Envelope).GetString());
        Assert.Equal(3, mapped["unknown"].GetProperty("values").GetArrayLength());
        Assert.Equal(snapshot, input.ToJsonString());
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData("seekable")]
    [InlineData("nonseekable")]
    [InlineData("pooled")]
    [InlineData("pooled-offset")]
    public void FromStreamValidatesLargeRawItemFromCurrentPositionBeforePocoMappingAndOwnsInput(string kind)
    {
        using Harness h = new();
        JsonObject raw = JsonNode.Parse(Document)!.AsObject();
        raw["notInPoco"] = new string('x', 40_000);
        byte[] signed = h.Sign(raw.ToJsonString());
        Stream source;
        if (kind.StartsWith("pooled", StringComparison.Ordinal))
        {
            RecyclableMemoryStream pooled = h.Processor.Buffers.Rent();
            if (kind == "pooled-offset") pooled.Write("prefix:"u8);
            long start = pooled.Position;
            pooled.Write(signed);
            pooled.Position = start;
            source = pooled;
        }
        else
        {
            source = new TrackingInput([.. "prefix:"u8, .. signed], kind == "seekable", start: 7, maxRead: 113);
        }
        using (source)
        {
            Item item = h.Serializer.FromStream<Item>(source);
            Assert.Equal("one", item.Id);
            Assert.Equal("tenant", item.Pk);
            Assert.Equal("First item", item.DisplayName);
            Assert.Equal(7, item.Value);
            Assert.False(source.CanRead);
            if (source is TrackingInput tracked) Assert.Equal(1, tracked.DisposeCalls);
            Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
        }
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(false, 2)]
    [InlineData(true, 2)]
    public void SignedArraysAndEmptyFeedArrayMapWithoutRootEnvelopes(bool injected, int count)
    {
        using Harness h = new();
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = injected ? new(h.Processor, mapper) : h.Serializer;
        JsonArray array = new();
        for (int index = 0; index < count; index++)
            array.Add(JsonNode.Parse(h.Sign($"{{\"id\":\"item-{index}\",\"pk\":\"tenant\",\"value\":{index}}}")));
        using TrackingInput input = new(Encoding.UTF8.GetBytes(array.ToJsonString()), seekable: false, maxRead: 17);

        JsonElement[] items = serializer.FromStream<JsonElement[]>(input);

        Assert.Equal(count, items.Length);
        for (int index = 0; index < count; index++)
        {
            Assert.Equal($"item-{index}", items[index].GetProperty("id").GetString());
            Assert.Equal(index, items[index].GetProperty("value").GetInt32());
            Assert.False(items[index].TryGetProperty(Envelope, out _));
        }
        Assert.Equal(injected ? 1 : 0, mapper.ReadCalls);
        Assert.Equal(1, input.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidLaterArrayItemPreventsAnyDelegateMaterialization(bool missingSignature)
    {
        using Harness h = new();
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        JsonObject valid = JsonNode.Parse(h.Sign(Document))!.AsObject();
        JsonObject invalid = (JsonObject)valid.DeepClone();
        if (missingSignature) invalid.Remove(Envelope);
        else invalid["value"] = 8;
        JsonArray array = new(valid.DeepClone(), invalid, valid.DeepClone());
        using TrackingInput source = new(Encoding.UTF8.GetBytes(array.ToJsonString()));

        ContentValidationException failure = Assert.Throws<ContentValidationException>(() => serializer.FromStream<Item[]>(source));

        Assert.Equal(missingSignature ? ContentValidationFailure.MissingSignature : ContentValidationFailure.InvalidSignature, failure.Failure);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Null(mapper.View);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void DefaultMapperDoesNotConstructEarlierArrayItemsBeforeLaterItemValidation()
    {
        using Harness h = new();
        JsonObject first = JsonNode.Parse(h.Sign(Document))!.AsObject();
        JsonObject later = (JsonObject)first.DeepClone();
        later["value"] = 8;
        using TrackingInput source = new(Encoding.UTF8.GetBytes(new JsonArray(first, later).ToJsonString()));
        ConstructionProbe.Constructions = 0;

        ContentValidationException failure = Assert.Throws<ContentValidationException>(
            () => h.Serializer.FromStream<ConstructionProbe[]>(source));

        Assert.Equal(ContentValidationFailure.InvalidSignature, failure.Failure);
        Assert.Equal(0, ConstructionProbe.Constructions);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData("missing", ContentValidationFailure.MissingSignature)]
    [InlineData("malformed", ContentValidationFailure.InvalidSignature)]
    [InlineData("signature", ContentValidationFailure.InvalidSignature)]
    [InlineData("known-field", ContentValidationFailure.InvalidSignature)]
    [InlineData("unknown-change", ContentValidationFailure.InvalidSignature)]
    [InlineData("unknown-remove", ContentValidationFailure.InvalidSignature)]
    [InlineData("unknown-add", ContentValidationFailure.InvalidSignature)]
    [InlineData("unknown-key", ContentValidationFailure.UnknownKey)]
    public void MissingOrInvalidRawSignatureNeverReachesMapperIncludingFieldsOutsidePoco(string change, ContentValidationFailure expected)
    {
        using Harness h = new();
        JsonObject raw = JsonNode.Parse(Document)!.AsObject();
        raw["notInPoco"] = new JsonObject { ["protected"] = true };
        JsonObject signed = JsonNode.Parse(h.Sign(raw.ToJsonString()))!.AsObject();
        switch (change)
        {
            case "missing": signed.Remove(Envelope); break;
            case "malformed": signed[Envelope] = new JsonObject(); break;
            case "signature":
                string signature = signed[Envelope]!["signature"]!.GetValue<string>();
                signed[Envelope]!["signature"] = (signature[0] == 'A' ? "B" : "A") + signature[1..];
                break;
            case "known-field": signed["value"] = 8; break;
            case "unknown-change": signed["notInPoco"]!["protected"] = false; break;
            case "unknown-remove": signed.Remove("notInPoco"); break;
            case "unknown-add": signed["anotherUnknownField"] = 1; break;
            case "unknown-key": signed[Envelope]!["kid"] = "untrusted-key"; break;
        }
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using TrackingInput source = new(Encoding.UTF8.GetBytes(signed.ToJsonString()));

        ContentValidationException failure = Assert.Throws<ContentValidationException>(() => serializer.FromStream<Item>(source));

        Assert.Equal(expected, failure.Failure);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" \r\n\t")]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("42")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    [InlineData("{")]
    public void EmptyMalformedAndScalarBodiesFailClosedInsteadOfMappingDefaultValues(string body)
    {
        // HTTP no-content success is handled by the wrapper; a direct serializer call needs JSON.
        using Harness h = new();
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using TrackingInput source = new(Encoding.UTF8.GetBytes(body));
        ContentValidationException failure = Assert.Throws<ContentValidationException>(() => serializer.FromStream<Item>(source));
        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("42")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    public void ToStreamRejectsNonDocumentValuesAndReleasesItsMappingBuffer(string body)
    {
        using Harness h = new();
        using JsonDocument input = JsonDocument.Parse(body);
        ContentValidationException failure = Assert.Throws<ContentValidationException>(() => h.Serializer.ToStream(input.RootElement));
        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RefusingStreamTargetsStillDisposesFromStreamInputBeforeAnyRead(bool derived)
    {
        using Harness h = new();
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using TrackingInput source = new(h.Sign(Document));
        if (derived) Assert.Throws<NotSupportedException>(() => serializer.FromStream<MemoryStream>(source));
        else Assert.Throws<NotSupportedException>(() => serializer.FromStream<Stream>(source));
        Assert.Equal(0, source.ReadCalls);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void RefusingRawToStreamInputsDoesNotTakeOwnershipOfCallerStream()
    {
        using Harness h = new();
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using MemoryStream source = new(Encoding.UTF8.GetBytes(Document));
        Assert.Throws<NotSupportedException>(() => serializer.ToStream<Stream>(source));
        Assert.Throws<NotSupportedException>(() => serializer.ToStream(source));
        Assert.Throws<NotSupportedException>(() => serializer.ToStream<object>(source));
        Assert.True(source.CanRead);
        Assert.Equal(0L, source.Position);
        Assert.Equal(0, mapper.WriteCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InjectedMapperControlsMappingAndItsOutputIsReadFromCurrentPositionThenDisposed(bool seekable)
    {
        using Harness h = new();
        JsonSerializerOptions options = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
        ProbeSerializer mapper = new(options);
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        Item item = new() { Id = "custom", Pk = "tenant", DisplayName = "Custom mapping", Value = 9 };
        byte[] raw = JsonSerializer.SerializeToUtf8Bytes(item, options);
        using TrackingInput delegated = new([.. "prefix:"u8, .. raw], seekable, start: 7, maxRead: 23);
        mapper.WriteFactory = _ => delegated;
        using (RecyclableMemoryStream output = Assert.IsType<RecyclableMemoryStream>(serializer.ToStream(item)))
        {
            Assert.Same(item, mapper.WrittenInput);
            Assert.Equal(1, mapper.WriteCalls);
            Assert.Equal(1, delegated.DisposeCalls);
            Assert.Equal(0L, output.Position);
            h.Processor.Validate(output.GetReadOnlySequence());
            using JsonDocument document = JsonDocument.Parse(output.GetReadOnlySequence());
            Assert.Equal("Custom mapping", document.RootElement.GetProperty("display_name").GetString());
            Assert.False(document.RootElement.TryGetProperty("displayName", out _));
            Item mapped = serializer.FromStream<Item>(h.Processor.Buffers.Read(output));
            Assert.Equal(item.DisplayName, mapped.DisplayName);
            Assert.Equal(item.Id, mapped.Id);
            Assert.Equal(1, mapper.ReadCalls);
            Assert.False(mapper.MappedJson!.ContainsKey(Envelope));
            Assert.True(output.CanRead);
            Assert.True(h.Processor.Buffers.InUseBytes > 0);
        }
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void DelegateViewIsReadOnlyAndPoolOwnerIsReleasedEvenIfDelegateThrowsOrDisposesTwice(bool disposeView, bool throws)
    {
        using Harness h = new();
        InvalidOperationException sentinel = new("mapping failed");
        ProbeSerializer mapper = new()
        {
            DisposeView = disposeView,
            ReadFailure = throws ? sentinel : null,
            BeforeRead = view =>
            {
                Assert.True(view.CanRead);
                Assert.True(view.CanSeek);
                Assert.False(view.CanWrite);
                Assert.Equal(0L, view.Position);
                Assert.Throws<NotSupportedException>(() => view.WriteByte(0));
                Assert.Throws<NotSupportedException>(() => view.SetLength(0));
                Assert.Equal((int)'{', view.ReadByte());
                Assert.Equal(0L, view.Seek(0, SeekOrigin.Begin));
                Assert.True(h.Processor.Buffers.InUseBytes > 0);
            }
        };
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using TrackingInput source = new(h.Sign(Document));
        if (throws) Assert.Same(sentinel, Assert.Throws<InvalidOperationException>(() => serializer.FromStream<Item>(source)));
        else Assert.Equal("one", serializer.FromStream<Item>(source).Id);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(1, mapper.ReadCalls);
        Assert.False(mapper.MappedJson!.ContainsKey(Envelope));
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);

        using (RecyclableMemoryStream active = h.Processor.Buffers.Rent())
        {
            active.Write("still leased"u8);
            long inUse = h.Processor.Buffers.InUseBytes;
            Assert.NotNull(mapper.View);
            mapper.View.Dispose();
            mapper.View.Dispose();
            Assert.Equal(inUse, h.Processor.Buffers.InUseBytes);
            Assert.Equal("still leased"u8.ToArray(), active.GetReadOnlySequence().ToArray());
        }
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void ToStreamReleasesInjectedOutputWhenSigningFailsAndPropagatesDelegateException()
    {
        using Harness h = new();
        using TrackingInput invalid = new("42"u8.ToArray());
        ProbeSerializer mapper = new() { WriteFactory = _ => invalid };
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        ContentValidationException failure = Assert.Throws<ContentValidationException>(() => serializer.ToStream(new Item()));
        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Equal(1, invalid.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
        InvalidOperationException sentinel = new("serialize failed");
        mapper.WriteFactory = _ => throw sentinel;
        Assert.Same(sentinel, Assert.Throws<InvalidOperationException>(() => serializer.ToStream(new Item())));
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void FromStreamDisposesInputAndReleasesPartialCopyWhenReadingThrows()
    {
        using Harness h = new();
        IOException sentinel = new("input read failed");
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using TrackingInput source = new(h.Sign(Document), maxRead: 17) { FailOnRead = 2, ReadFailure = sentinel };

        Assert.Same(sentinel, Assert.Throws<IOException>(() => serializer.FromStream<Item>(source)));

        Assert.Equal(2, source.ReadCalls);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void ReturnedOutputIsNotReusedWhilePartiallyConsumedOrReplayed()
    {
        using Harness h = new();
        using (RecyclableMemoryStream first = Assert.IsType<RecyclableMemoryStream>(h.Serializer.ToStream(
            new Item { Id = "first", Pk = "tenant", DisplayName = new string('a', 40_000) })))
        {
            byte[] snapshot = first.GetReadOnlySequence().ToArray();
            byte[] prefix = new byte[29];
            first.ReadExactly(prefix);
            Assert.Equal(snapshot[..29], prefix);
            for (int index = 0; index < 12; index++)
            {
                using Stream other = h.Serializer.ToStream(new Item { Id = $"other-{index}", Pk = "tenant", DisplayName = new string('z', 40_000) });
                Assert.NotSame(first, other);
                Assert.Equal(29L, first.Position);
                Assert.Equal(snapshot, first.GetReadOnlySequence().ToArray());
            }
            byte[] remainder = new byte[snapshot.Length - prefix.Length];
            first.ReadExactly(remainder);
            Assert.Equal(snapshot[29..], remainder);
            first.Position = 0;
            h.Processor.Validate(first.GetReadOnlySequence());
            Assert.True(h.Processor.Buffers.InUseBytes > 0);
        }
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public async Task ConcurrentCallsShareOnlyThePoolNotReturnedStreamContentsOrCursors()
    {
        using Harness h = new();
        const int workers = 12;
        int ready = 0;
        TaskCompletionSource allReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await Task.WhenAll(Enumerable.Range(0, workers).Select(index => Task.Run(async () =>
        {
            Item item = new() { Id = $"item-{index}", Pk = "tenant", DisplayName = new string((char)('a' + index), 20_000), Value = index };
            using RecyclableMemoryStream output = Assert.IsType<RecyclableMemoryStream>(h.Serializer.ToStream(item));
            output.Position = index + 1;
            if (Interlocked.Increment(ref ready) == workers) allReady.TrySetResult();
            await allReady.Task.WaitAsync(TimeSpan.FromSeconds(30));
            Assert.Equal(index + 1L, output.Position);
            h.Processor.Validate(output.GetReadOnlySequence());
            using JsonDocument parsed = JsonDocument.Parse(output.GetReadOnlySequence());
            Assert.Equal(item.Id, parsed.RootElement.GetProperty("id").GetString());
            Assert.Equal(item.DisplayName, parsed.RootElement.GetProperty("displayName").GetString());
            output.Position = 0;
            Item mapped = h.Serializer.FromStream<Item>(h.Processor.Buffers.Read(output));
            Assert.Equal(item.Id, mapped.Id);
            Assert.Equal(item.Value, mapped.Value);
            Assert.Equal(0L, output.Position);
        })));
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InjectedValidatorSeesWholeRawItemsBeforeCanonicalizationAndMapping(bool array)
    {
        RecordingCanonicalizer canonicalizer = new();
        using Harness h = new(canonicalizer);
        // Construction canonicalizes the policy through this same injected provider.
        JsonElement policy = Assert.Single(canonicalizer.CanonicalInputs);
        Assert.Equal("root", policy.GetProperty("scope").GetString());
        Assert.Equal(1, policy.GetProperty("version").GetInt32());
        Assert.Equal(5, policy.GetProperty("ignoredProperties").GetArrayLength());
        JsonObject raw = JsonNode.Parse(Document)!.AsObject();
        raw["_etag"] = new JsonObject { ["ignoredButValidated"] = true };
        raw["outsidePoco"] = new JsonObject { ["protected"] = true };
        string signed = Encoding.UTF8.GetString(h.Sign(raw.ToJsonString()));
        canonicalizer.Clear(); // Exclude policy construction and preparation of the signed input.
        int count = array ? 2 : 1;
        ProbeSerializer mapper = new()
        {
            BeforeRead = view =>
            {
                Assert.Equal(count, canonicalizer.ValidatedInputs.Count);
                Assert.All(canonicalizer.ValidatedInputs, input =>
                {
                    Assert.Equal(JsonValueKind.Object, input.GetProperty(Envelope).ValueKind);
                    Assert.True(input.GetProperty("_etag").GetProperty("ignoredButValidated").GetBoolean());
                    Assert.True(input.GetProperty("outsidePoco").GetProperty("protected").GetBoolean());
                });
                Assert.Equal(2 * count, canonicalizer.CanonicalInputs.Count); // Document plus header per item.
                Assert.DoesNotContain(canonicalizer.CanonicalInputs, input => input.TryGetProperty("_etag", out _));
            }
        };
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using TrackingInput source = new(Encoding.UTF8.GetBytes(array ? "[" + signed + "," + signed + "]" : signed));

        if (array) Assert.Equal(2, serializer.FromStream<Item[]>(source).Length);
        else Assert.Equal("one", serializer.FromStream<Item>(source).Id);

        Assert.Equal(1, mapper.ReadCalls);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InjectedValidatorFailureStopsAllMappingAndCanonicalizationIncludingLaterArrayItems(bool array)
    {
        RecordingCanonicalizer canonicalizer = new();
        using Harness h = new(canonicalizer);
        string signed = Encoding.UTF8.GetString(h.Sign(Document));
        canonicalizer.Clear(); // Faults apply only to the read, not policy hashing or fixture signing.
        int failOnCall = array ? 2 : 1;
        canonicalizer.AfterValidation = _ =>
        {
            if (canonicalizer.ValidatedInputs.Count == failOnCall)
                throw new JsonException("sensitive-validator-diagnostic");
        };
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);
        using TrackingInput source = new(Encoding.UTF8.GetBytes(array ? "[" + signed + "," + signed + "]" : signed));

        ContentValidationException failure = Assert.Throws<ContentValidationException>(() =>
        {
            if (array) serializer.FromStream<Item[]>(source);
            else serializer.FromStream<Item>(source);
        });

        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.DoesNotContain("sensitive-validator-diagnostic", failure.ToString());
        Assert.Equal(failOnCall, canonicalizer.ValidatedInputs.Count);
        Assert.Empty(canonicalizer.CanonicalInputs);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Null(mapper.View);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData("{\"duplicate\":1,\"duplicate\":2}")]
    [InlineData("{\"number\":9007199254740992}")]
    [InlineData("{\"text\":\"\\ud800\"}")]
    public void InjectedValidatorRejectsMalformedIgnoredSubtreesBeforeMapper(string ignoredSubtree)
    {
        RecordingCanonicalizer canonicalizer = new();
        using Harness h = new(canonicalizer);
        string signed = Encoding.UTF8.GetString(h.Sign(Document));
        canonicalizer.Clear();
        // The signature still authenticates the protected fields, but ignored raw JSON must be valid too.
        using TrackingInput source = new(Encoding.UTF8.GetBytes(signed[..^1] + ",\"_etag\":" + ignoredSubtree + "}"));
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(h.Processor, mapper);

        ContentValidationException failure = Assert.Throws<ContentValidationException>(() => serializer.FromStream<Item>(source));

        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
        Assert.Single(canonicalizer.ValidatedInputs);
        Assert.Empty(canonicalizer.CanonicalInputs);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Null(mapper.View);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InjectedCryptoProviderFailuresPropagateUnchangedAndReleaseSerializerBuffers(bool signing)
    {
        using Harness h = new();
        CryptographicException sentinel = new("crypto provider sentinel");
        ThrowingCryptoProvider provider = new(sentinel);
        ContentValidationProcessor processor = UnsafeSampleProviders.CreateProcessor(new(),
            new UnsafeInMemoryVerificationKeyResolver([provider]), provider);
        ProbeSerializer mapper = new();
        ContentValidationSerializer serializer = new(processor, mapper);
        using TrackingInput source = new(signing ? Encoding.UTF8.GetBytes(Document) : h.Sign(Document));
        mapper.WriteFactory = _ => source;

        if (signing)
            Assert.Same(sentinel, Assert.Throws<CryptographicException>(() => serializer.ToStream(new Item())));
        else
            Assert.Same(sentinel, Assert.Throws<CryptographicException>(() => serializer.FromStream<Item>(source)));

        Assert.Equal(signing ? 1 : 0, provider.SignCalls);
        Assert.Equal(signing ? 0 : 1, provider.VerifyCalls);
        Assert.Equal(signing ? 1 : 0, mapper.WriteCalls);
        Assert.Equal(0, mapper.ReadCalls);
        Assert.Equal(1, source.DisposeCalls);
        Assert.Equal(0L, processor.Buffers.InUseBytes);
        Assert.Equal(0L, h.Processor.Buffers.InUseBytes);
    }

    public sealed class Item
    {
        public string Id { get; set; } = "";
        public string Pk { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public int Value { get; set; }
    }

    public sealed class ConstructionProbe
    {
        public static int Constructions;
        public ConstructionProbe() => Interlocked.Increment(ref Constructions);
        public string Id { get; set; } = "";
    }

    private sealed class Harness : IDisposable
    {
        private readonly UnsafeEcdsaContentSigner signer;
        private readonly UnsafeEcdsaContentVerifier verifier;
        public ContentValidationProcessor Processor { get; }
        public ContentValidationSerializer Serializer { get; }

        public Harness(IJsonCanonicalizer? canonicalizer = null)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            signer = new("ephemeral-serializer-test", key.ExportPkcs8PrivateKeyPem());
            verifier = new(signer.KeyId, key.ExportSubjectPublicKeyInfoPem());
            Processor = UnsafeSampleProviders.CreateProcessor(new(), new UnsafeInMemoryVerificationKeyResolver([verifier]),
                signer, canonicalizer: canonicalizer);
            Serializer = new(Processor);
        }

        public byte[] Sign(string json)
        {
            using RecyclableMemoryStream signed = Processor.Sign(new(Encoding.UTF8.GetBytes(json)));
            return signed.GetReadOnlySequence().ToArray();
        }

        public void Dispose()
        {
            signer.Dispose();
            verifier.Dispose();
        }
    }

    private sealed class RecordingCanonicalizer : IJsonCanonicalizer
    {
        private readonly UnsafeJcsCanonicalizer inner = new();
        public string ProfileId => inner.ProfileId;
        public List<JsonElement> ValidatedInputs { get; } = [];
        public List<JsonElement> CanonicalInputs { get; } = [];
        public Action<JsonElement>? AfterValidation { get; set; }

        public void ValidateInput(JsonElement value)
        {
            ValidatedInputs.Add(value.Clone());
            inner.ValidateInput(value);
            AfterValidation?.Invoke(value);
        }

        public void Canonicalize(JsonElement value, IBufferWriter<byte> destination)
        {
            CanonicalInputs.Add(value.Clone());
            inner.Canonicalize(value, destination);
        }

        public void Clear()
        {
            ValidatedInputs.Clear();
            CanonicalInputs.Clear();
        }
    }

    private sealed class ThrowingCryptoProvider(CryptographicException failure) : IContentSigner, IContentVerifier
    {
        public string KeyId => "ephemeral-serializer-test";
        public string AlgorithmId => "ECDSA-P256-SHA256-P1363";
        public int SignCalls { get; private set; }
        public int VerifyCalls { get; private set; }
        public byte[] SignHash(ReadOnlySpan<byte> hash) { SignCalls++; throw failure; }
        public bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature) { VerifyCalls++; throw failure; }
    }

    private sealed class ProbeSerializer(JsonSerializerOptions? options = null) : CosmosSerializer
    {
        private readonly JsonSerializerOptions options = options ?? new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        public int ReadCalls { get; private set; }
        public int WriteCalls { get; private set; }
        public object? WrittenInput { get; private set; }
        public Stream? View { get; private set; }
        public JsonObject? MappedJson { get; private set; }
        public Action<Stream>? BeforeRead { get; init; }
        public bool DisposeView { get; init; } = true;
        public Exception? ReadFailure { get; init; }
        public Func<object?, Stream>? WriteFactory { get; set; }

        public override T FromStream<T>(Stream stream)
        {
            ReadCalls++;
            View = stream;
            try
            {
                BeforeRead?.Invoke(stream);
                using JsonDocument parsed = JsonDocument.Parse(stream);
                if (parsed.RootElement.ValueKind == JsonValueKind.Object)
                    MappedJson = JsonNode.Parse(parsed.RootElement.GetRawText())!.AsObject();
                if (ReadFailure is not null) throw ReadFailure;
                return parsed.RootElement.Deserialize<T>(options)!;
            }
            finally
            {
                if (DisposeView)
                {
                    stream.Dispose();
                    stream.Dispose();
                }
            }
        }

        public override Stream ToStream<T>(T input)
        {
            WriteCalls++;
            WrittenInput = input;
            return WriteFactory is not null ? WriteFactory(input) : new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(input, options));
        }
    }

    private sealed class TrackingInput(byte[] bytes, bool seekable = true, int start = 0, int maxRead = int.MaxValue) : Stream
    {
        private readonly MemoryStream inner = new(bytes, writable: false) { Position = start };
        public int DisposeCalls { get; private set; }
        public int ReadCalls { get; private set; }
        public int FailOnRead { get; init; } = -1;
        public IOException? ReadFailure { get; init; }
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => seekable && inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => seekable ? inner.Length : throw new NotSupportedException();
        public override long Position
        {
            get => seekable ? inner.Position : throw new NotSupportedException();
            set { if (!seekable) throw new NotSupportedException(); inner.Position = value; }
        }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            ReadCalls++;
            if (ReadCalls == FailOnRead) throw ReadFailure ?? new IOException("input read failed");
            return inner.Read(buffer[..Math.Min(buffer.Length, maxRead)]);
        }
        public override long Seek(long offset, SeekOrigin origin) => seekable ? inner.Seek(offset, origin) : throw new NotSupportedException();
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) { DisposeCalls++; inner.Dispose(); }
            base.Dispose(disposing);
        }
    }
}