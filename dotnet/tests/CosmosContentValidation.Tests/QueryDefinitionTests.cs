using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CosmosContentValidation.Sample.Providers;
using Microsoft.Azure.Cosmos;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class QueryDefinitionTests
{
    [Fact]
    public void ExactTextOrderedReplacementAndOrdinaryParametersRemainUnsigned()
    {
        using Harness harness = new();
        Mutable value = new() { Id = "application-id", ContentValidation = "application-data", Value = 1 };
        ContentValidationQueryDefinition definition = new ContentValidationQueryDefinition(" SELECT * FROM c WHERE c.id = @id ")
            .WithParameter("@first", new { value = 1 })
            .WithParameter("@null", null)
            .WithParameter("@first", value);

        QueryDefinition built = definition.Build(harness.Serializer);

        Assert.Equal(" SELECT * FROM c WHERE c.id = @id ", built.QueryText);
        Assert.Equal(new[] { "@null", "@first" }, built.GetQueryParameters().Select(parameter => parameter.Name));
        Assert.Equal(2, harness.Mapper.Json.Count);
        Assert.Equal("null", harness.Mapper.Json[0]);
        JsonObject mapped = JsonNode.Parse(harness.Mapper.Json[1])!.AsObject();
        Assert.Equal("application-id", mapped["id"]!.GetValue<string>());
        Assert.Equal("application-data", mapped["_contentValidation"]!.GetValue<string>());
        Assert.Equal(1, mapped["value"]!.GetValue<int>());
        Assert.Equal(0, harness.Processor.Buffers.InUseBytes);
    }

    [Fact]
    public void BuildSnapshotsMutableOrdinaryValuesAndEveryBuildIsFresh()
    {
        using Harness harness = new();
        Mutable value = new() { Id = "one", Value = 1 };
        ContentValidationQueryDefinition definition = new("SELECT * FROM c") { };
        definition.WithParameter("@value", value);

        QueryDefinition first = definition.Build(harness.Serializer);
        value.Id = "two";
        value.Value = 2;
        QueryDefinition second = definition.Build(harness.Serializer);

        Assert.NotSame(first, second);
        Assert.Equal(2, harness.Mapper.Json.Count);
        Assert.Equal("one", JsonNode.Parse(harness.Mapper.Json[0])!["id"]!.GetValue<string>());
        Assert.Equal(1, JsonNode.Parse(harness.Mapper.Json[0])!["value"]!.GetValue<int>());
        Assert.Equal("two", JsonNode.Parse(harness.Mapper.Json[1])!["id"]!.GetValue<string>());
        Assert.Equal(2, JsonNode.Parse(harness.Mapper.Json[1])!["value"]!.GetValue<int>());
        Assert.All(harness.Mapper.Streams, stream => Assert.False(stream.CanRead));
        Assert.All(harness.Mapper.Streams, stream => Assert.Equal(1, stream.DisposeCalls));
    }

    [Fact]
    public void StreamParameterConsumesFromCurrentPositionDisposesOnceAndSnapshotsImmediately()
    {
        using Harness harness = new();
        TrackingStream input = new(Encoding.UTF8.GetBytes("prefix:{\"x\":1}"));
        input.Position = 7;
        ContentValidationQueryDefinition definition = new("SELECT * FROM c");

        Assert.Same(definition, definition.WithParameterStream("@raw", input));

        Assert.Equal(1, input.DisposeCalls);
        Assert.True(input.ReadCalls > 0);
        Assert.False(input.CanRead);
        QueryDefinition first = definition.Build(harness.Serializer);
        QueryDefinition second = definition.Build(harness.Serializer);
        Assert.Equal("@raw", Assert.Single(first.GetQueryParameters()).Name);
        Assert.Equal("@raw", Assert.Single(second.GetQueryParameters()).Name);
        Assert.Empty(harness.Mapper.Json);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("\"text\"")]
    [InlineData("[1,true,null]")]
    [InlineData("{\"id\":\"not-a-document\",\"_contentValidation\":\"ordinary-data\"}")]
    public void RawJsonAcceptsExactlyOneStrictValueWithoutOrdinarySerialization(string json)
    {
        using Harness harness = new();
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        ContentValidationQueryDefinition definition = new("SELECT * FROM c");
        Assert.Same(definition, definition.WithRawJsonParameter("@raw", bytes));
        Array.Fill(bytes, (byte)'x');

        QueryDefinition built = definition.Build(harness.Serializer);

        Assert.Equal("@raw", Assert.Single(built.GetQueryParameters()).Name);
        Assert.Empty(harness.Mapper.Json);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1 2")]
    [InlineData("{\"x\":1}{\"y\":2}")]
    [InlineData("{\"x\":1,}")]
    [InlineData("{/*comment*/\"x\":1}")]
    [InlineData("{\"x\":1,\"x\":2}")]
    [InlineData("{\"x\":1,\"\\u0078\":2}")]
    [InlineData("\"\\uD800\"")]
    public void RawJsonRejectsMalformedMultipleDuplicateAndInvalidUnicode(string json)
    {
        ContentValidationQueryDefinition definition = new("SELECT * FROM c");
        ContentValidationException failure = Assert.Throws<ContentValidationException>(
            () => definition.WithRawJsonParameter("@raw", Encoding.UTF8.GetBytes(json)));
        Assert.Equal(ContentValidationFailure.InvalidDocument, failure.Failure);
    }

    [Fact]
    public void RawJsonRejectsInvalidUtf8AndOversizeBeforeBuild()
    {
        ContentValidationQueryDefinition definition = new("SELECT * FROM c");
        Assert.Equal(ContentValidationFailure.InvalidDocument,
            Assert.Throws<ContentValidationException>(() => definition.WithRawJsonParameter("@raw", new byte[] { 0xFF })).Failure);
        Assert.Equal(ContentValidationFailure.PayloadTooLarge,
            Assert.Throws<ContentValidationException>(() => definition.WithRawJsonParameter("@raw", new byte[1024 * 1024 + 1])).Failure);
        using TrackingStream oversized = new(new byte[1024 * 1024 + 1]);
        Assert.Equal(ContentValidationFailure.PayloadTooLarge,
            Assert.Throws<ContentValidationException>(() => definition.WithParameterStream("@raw", oversized)).Failure);
        Assert.Equal(1, oversized.DisposeCalls);
    }

    [Fact]
    public void BaseApiBypassIsRejectedBeforeOrdinarySerialization()
    {
        using Harness harness = new();
        ContentValidationQueryDefinition definition = new("SELECT * FROM c");
        ((QueryDefinition)definition).WithParameter("@bypass", new { id = "unsafe" });

        ContentValidationException failure = Assert.Throws<ContentValidationException>(() => definition.Build(harness.Serializer));

        Assert.Equal(ContentValidationFailure.UnsupportedOperation, failure.Failure);
        Assert.Empty(harness.Mapper.Json);
    }

    [Fact]
    public void BuildFailureReleasesEveryProducedParameterStream()
    {
        using Harness harness = new();
        harness.Mapper.FailOnCall = 2;
        ContentValidationQueryDefinition definition = new("SELECT * FROM c");
        definition.WithParameter("@one", 1).WithParameter("@two", 2);

        Assert.Throws<InvalidOperationException>(() => definition.Build(harness.Serializer));

        TrackingStream first = Assert.Single(harness.Mapper.Streams);
        Assert.False(first.CanRead);
        Assert.True(first.DisposeCalls >= 1);
    }

    [Fact]
    public void NamesMatchNativeNullAndEmptyValidation()
    {
        ContentValidationQueryDefinition definition = new("SELECT * FROM c");
        Assert.Throws<ArgumentNullException>(() => definition.WithParameter(null!, 1));
        Assert.Throws<ArgumentNullException>(() => definition.WithParameter("", 1));
        Assert.Throws<ArgumentNullException>(() => definition.WithRawJsonParameter(null!, "1"u8.ToArray()));
        Assert.Throws<ArgumentNullException>(() => definition.WithParameterStream("", new MemoryStream("1"u8.ToArray())));
    }

    private sealed class Harness : IDisposable
    {
        public ContentValidationProcessor Processor { get; }
        public RecordingSerializer Mapper { get; } = new();
        public ContentValidationSerializer Serializer { get; }

        public Harness()
        {
            Processor = UnsafeSampleProviders.CreateProcessor(new(), new NoKeys());
            Serializer = new ContentValidationSerializer(Processor, Mapper);
        }

        public void Dispose() => Assert.Equal(0, Processor.Buffers.InUseBytes);
    }

    private sealed class NoKeys : IVerificationKeyResolver
    {
        public IContentVerifier? Resolve(string keyId) => null;
    }

    private sealed class Mutable
    {
        public string Id { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("_contentValidation")]
        public string ContentValidation { get; set; } = "";
        public int Value { get; set; }
    }

    private sealed class RecordingSerializer : CosmosSerializer
    {
        public List<string> Json { get; } = [];
        public List<TrackingStream> Streams { get; } = [];
        public int FailOnCall { get; set; } = -1;
        private int calls;

        public override T FromStream<T>(Stream stream) => throw new NotSupportedException();

        public override Stream ToStream<T>(T input)
        {
            calls++;
            if (calls == FailOnCall) throw new InvalidOperationException("parameter serialization failed");
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(input, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            Json.Add(Encoding.UTF8.GetString(bytes));
            TrackingStream stream = new(bytes);
            Streams.Add(stream);
            return stream;
        }
    }

    private sealed class TrackingStream(byte[] bytes) : MemoryStream(bytes)
    {
        public int ReadCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadCalls++;
            return base.Read(buffer, offset, Math.Min(count, 127));
        }
        public override int Read(Span<byte> buffer)
        {
            ReadCalls++;
            return base.Read(buffer[..Math.Min(buffer.Length, 127)]);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeCalls++;
            base.Dispose(disposing);
        }
    }
}
