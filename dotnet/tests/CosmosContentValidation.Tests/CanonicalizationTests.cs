using System.Buffers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using CosmosContentValidation.Sample.Providers;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class CanonicalizationTests
{
    // Keep direct coverage of the sample provider's internal validator as well as
    // its public interface entry point, without granting assembly-wide friend access.
    private static readonly Action<JsonElement> ValidateInput = typeof(UnsafeJcsCanonicalizer).Assembly
        .GetType("CosmosContentValidation.Sample.Providers.UnsafeJsonInputValidation", throwOnError: true)!
        .GetMethod("Validate", BindingFlags.NonPublic | BindingFlags.Static)!
        .CreateDelegate<Action<JsonElement>>();

    [Fact]
    public void ProfileAndInterfaceAreStableAndSynchronous()
    {
        IJsonCanonicalizer canonicalizer = new UnsafeJcsCanonicalizer();
        Assert.Equal("rfc8785-binary64-v1", UnsafeJcsCanonicalizer.SupportedProfileId);
        Assert.Equal(UnsafeJcsCanonicalizer.SupportedProfileId, canonicalizer.ProfileId);
        using JsonDocument document = JsonDocument.Parse("{\"b\":2,\"a\":1}");
        using BorrowedWriter destination = new();

        Action<JsonElement> synchronousValidation = canonicalizer.ValidateInput;
        synchronousValidation(document.RootElement);
        Assert.Equal(0, destination.RequestCount);
        Action<JsonElement, IBufferWriter<byte>> synchronousCall = canonicalizer.Canonicalize;
        synchronousCall(document.RootElement, destination);

        Assert.Equal("{\"a\":1,\"b\":2}", destination.Text);
        Assert.False(destination.IsDisposed);
        Assert.True(destination.RequestCount > 0);
        Assert.Equal(2, document.RootElement.GetProperty("b").GetInt32());
    }

    [Theory]
    [InlineData("null", "null")]
    [InlineData("true", "true")]
    [InlineData("false", "false")]
    [InlineData("{}", "{}")]
    [InlineData("[]", "[]")]
    [InlineData("\"\"", "\"\"")]
    [InlineData(" { \"b\" : 2, \"a\" : 1 } ", "{\"a\":1,\"b\":2}")]
    [InlineData("[3,1,2,{\"b\":true,\"a\":null},[false,true]]", "[3,1,2,{\"a\":null,\"b\":true},[false,true]]")]
    [InlineData("{\"a\":{\"x\":1},\"b\":{\"x\":2},\"A\":3}", "{\"A\":3,\"a\":{\"x\":1},\"b\":{\"x\":2}}")]
    public void CanonicalizesScalarsObjectsAndArrays(string json, string expected)
    {
        Assert.Equal(expected, Canonicalize(json));
    }

    [Fact]
    public void SortsDecodedNamesByUtf16CodeUnitsRatherThanCodePoints()
    {
        const string json = """
            {"\ufb33":"BMP","\ud83d\ude00":"Astral","\u20ac":"Euro","\u00f6":"O",
             "\u0080":"Control","1":"One","\r":"Carriage Return"}
            """;
        const string expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"O\",\"\u20ac\":\"Euro\",\"\U0001f600\":\"Astral\",\"\ufb33\":\"BMP\"}";

        Assert.Equal(expected, Canonicalize(json));
    }

    [Fact]
    public void MinimallyEscapesControlsAndLeavesOtherUnicodeAndSlashLiteral()
    {
        const string json = """{"s":"\u0000\u0001\b\t\n\f\r\u000b\u001f\"\\\/<>&\u2028\u2029"}""";
        const string expected = "{\"s\":\"\\u0000\\u0001\\b\\t\\n\\f\\r\\u000b\\u001f\\\"\\\\/<>&\u2028\u2029\"}";

        Assert.Equal(expected, Canonicalize(json));
    }

    [Fact]
    public void DoesNotNormalizeNamesOrValuesOrTreatOrdinallyDistinctNamesAsDuplicates()
    {
        const string json = """{"\u00e9":"\u00e9","e\u0301":"e\u0301","a":2,"A":1,"\ufffd":"\ufffd"}""";
        const string expected = "{\"A\":1,\"a\":2,\"e\u0301\":\"e\u0301\",\"\u00e9\":\"\u00e9\",\"\ufffd\":\"\ufffd\"}";

        Assert.Equal(expected, Canonicalize(json));
    }

    [Theory]
    [InlineData("-0", "0")]
    [InlineData("-0.000e+99", "0")]
    [InlineData("0e-999", "0")]
    [InlineData("0.000E+999", "0")]
    [InlineData("4.50", "4.5")]
    [InlineData("2e-3", "0.002")]
    [InlineData("1E-27", "1e-27")]
    [InlineData("1e-6", "0.000001")]
    [InlineData("1e-7", "1e-7")]
    [InlineData("333333333.33333329", "333333333.3333333")]
    [InlineData("1424953923781206.25", "1424953923781206.2")]
    [InlineData("9007199254740991", "9007199254740991")]
    [InlineData("-9007199254740991.0", "-9007199254740991")]
    [InlineData("9.007199254740991e15", "9007199254740991")]
    [InlineData("9007199254740991000e-3", "9007199254740991")]
    [InlineData("9007199254740991.0000000000000000001", "9007199254740991")]
    [InlineData("5e-324", "5e-324")]
    [InlineData("-5e-324", "-5e-324")]
    [InlineData("3e-324", "5e-324")]
    [InlineData("4.9406564584124654e-324", "5e-324")]
    public void NumbersUseBinary64RoundingAndEcmaScriptFormatting(string json, string expected)
    {
        Assert.Equal(expected, Canonicalize(json));
    }

    [Theory]
    [InlineData("9007199254740992")]
    [InlineData("-9007199254740992")]
    [InlineData("9007199254740993")]
    [InlineData("9007199254740992.0")]
    [InlineData("9.007199254740992e15")]
    [InlineData("-9.007199254740992E+15")]
    [InlineData("90071992547409920e-1")]
    [InlineData("0.0009007199254740992e19")]
    [InlineData("9007199254740992000e-3")]
    [InlineData("9007199254740991.5")]
    [InlineData("-9007199254740991.5")]
    [InlineData("18446744073709551615")]
    [InlineData("1E30")]
    [InlineData("1e309")]
    [InlineData("-1e309")]
    [InlineData("1e99999")]
    [InlineData("1e-324")]
    [InlineData("2e-324")]
    [InlineData("-1e-400")]
    [InlineData("100e-999")]
    [InlineData("0.000001e-999")]
    public void RejectsUnsafeIntegralResultsOverflowAndNonzeroUnderflow(string number)
    {
        using JsonDocument scalar = JsonDocument.Parse(number);
        AssertRejected(scalar.RootElement);

        // Root metadata is still validated before a processor can ignore it.
        using JsonDocument ignored = JsonDocument.Parse("{\"_etag\":{\"nested\":[" + number + "]}}");
        AssertRejected(ignored.RootElement);
        Assert.Equal("\"" + number + "\"", Canonicalize("\"" + number + "\""));
    }

    [Theory]
    [InlineData("{\"a\":1,\"a\":2}")]
    [InlineData("{\"a\":1,\"\\u0061\":2}")]
    [InlineData("{\"\":1,\"\":2}")]
    [InlineData("{\"\U0001f600\":1,\"\\ud83d\\ude00\":2}")]
    [InlineData("{\"nested\":[{\"a\":1,\"\\u0061\":2}]}")]
    [InlineData("{\"_etag\":{\"sensitive-property\":1,\"sensitive-property\":2}}")]
    [InlineData("{\"_etag\":1,\"\\u005fetag\":2}")]
    public void RejectsDuplicateDecodedNamesAtEveryDepth(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        AssertRejected(document.RootElement);
    }

    [Theory]
    [InlineData("\"\\ud800\"")]
    [InlineData("\"\\udfff\"")]
    [InlineData("\"\\ud800x\"")]
    [InlineData("\"\\udc00\\ud800\"")]
    [InlineData("\"\\ud800\\ud800\"")]
    [InlineData("{\"\\ud800\":1}")]
    [InlineData("{\"_etag\":\"sensitive-value\\ud800\"}")]
    [InlineData("{\"_etag\":{\"sensitive-property\\udfff\":1}}")]
    [InlineData("{\"custom-ignored\":[{\"value\":\"\\udc00\"}]}")]
    public void RejectsLazyUnpairedSurrogatesIncludingIgnoredPropertyContents(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        AssertRejected(document.RootElement);
    }

    public static IEnumerable<object[]> InvalidUtf8Inputs()
    {
        byte[][] invalidSequences =
        [
            [0x80],                  // Unattached continuation byte.
            [0xC0, 0xAF],            // Overlong encoding.
            [0xC3, 0x28],            // Invalid continuation.
            [0xED, 0xA0, 0x80],      // Encoded high surrogate.
            [0xED, 0xBF, 0xBF],      // Encoded low surrogate.
            [0xF4, 0x90, 0x80, 0x80], // Above U+10FFFF.
            [0xF0, 0x9F]             // Truncated sequence.
        ];
        foreach (byte[] invalid in invalidSequences)
        {
            yield return new object[] { Join("\"sensitive-value", invalid, "\"") };
            yield return new object[] { Join("{\"sensitive-property", invalid, "\":1}") };
            yield return new object[] { Join("{\"_etag\":\"sensitive-value", invalid, "\"}") };
            yield return new object[] { Join("{\"_etag\":[{\"sensitive-property", invalid, "\":1}]}") };
        }
    }

    [Theory]
    [MemberData(nameof(InvalidUtf8Inputs))]
    public void RejectsLazyInvalidUtf8IncludingIgnoredNamesAndValues(byte[] json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        AssertRejected(document.RootElement);
    }

    [Fact]
    public void AcceptsWellFormedSurrogatePairsAndLiteralUtf8()
    {
        const string escaped = "{\"\\ud83d\\ude00\":\"\\ud83d\\ude00\"}";
        const string literal = "{\"\U0001f600\":\"\U0001f600\"}";
        Assert.Equal(literal, Canonicalize(escaped));
        using JsonDocument document = JsonDocument.Parse(Encoding.UTF8.GetBytes(literal));
        ValidateInput(document.RootElement);
        ArrayBufferWriter<byte> destination = new();
        new UnsafeJcsCanonicalizer().Canonicalize(document.RootElement, destination);
        Assert.True(destination.WrittenSpan.SequenceEqual(Encoding.UTF8.GetBytes(literal)));
    }

    [Theory]
    [InlineData(false, "null")]
    [InlineData(true, "null")]
    [InlineData(false, "[]")]
    [InlineData(true, "{}")]
    public void EnforcesExactly64CollectionsCountingTheRoot(bool objects, string leaf)
    {
        // An empty collection leaf consumes a level; a scalar leaf does not.
        int leafDepth = leaf == "null" ? 0 : 1;
        string atLimit = Nest(64 - leafDepth, objects, leaf);
        using JsonDocument accepted = JsonDocument.Parse(atLimit, new JsonDocumentOptions { MaxDepth = 128 });
        ValidateInput(accepted.RootElement);
        ArrayBufferWriter<byte> destination = new();
        new UnsafeJcsCanonicalizer().Canonicalize(accepted.RootElement, destination);
        Assert.Equal(atLimit, Encoding.UTF8.GetString(destination.WrittenSpan));

        string overLimit = Nest(65 - leafDepth, objects, leaf);
        using JsonDocument rejected = JsonDocument.Parse(overLimit, new JsonDocumentOptions { MaxDepth = 128 });
        AssertRejected(rejected.RootElement);
    }

    [Fact]
    public void AlternatingCollectionsShareTheSameDepthBudget()
    {
        string json = "0";
        for (int depth = 0; depth < 64; depth++)
            json = depth % 2 == 0 ? "[" + json + "]" : "{\"x\":" + json + "}";
        Assert.Equal(json, Canonicalize(json));
        using JsonDocument rejected = JsonDocument.Parse("{\"_etag\":" + json + "}", new JsonDocumentOptions { MaxDepth = 128 });
        AssertRejected(rejected.RootElement);
    }

    [Fact]
    public void RejectsUndefinedAndNullDestination()
    {
        AssertRejected(default);
        using JsonDocument document = JsonDocument.Parse("null");
        Assert.Throws<ArgumentNullException>("destination", () => new UnsafeJcsCanonicalizer().Canonicalize(document.RootElement, null!));
    }

    [Fact]
    public void BorrowsPooledDestinationWithoutDisposalResetOrBodyFlattening()
    {
        PooledJsonBufferPool pool = new();
        using JsonDocument document = JsonDocument.Parse("{\"b\":2,\"a\":1}");
        IJsonCanonicalizer canonicalizer = new UnsafeJcsCanonicalizer();
        using (var stream = pool.Rent())
        {
            stream.Write("prefix:"u8);
            canonicalizer.Canonicalize(document.RootElement, stream);
            canonicalizer.Canonicalize(document.RootElement, stream);
            stream.WriteByte((byte)'!');
            Assert.True(stream.CanRead);
            Assert.Equal("prefix:{\"a\":1,\"b\":2}{\"a\":1,\"b\":2}!", Encoding.UTF8.GetString(stream.GetReadOnlySequence().FirstSpan));
            Assert.Equal(1, document.RootElement.GetProperty("a").GetInt32());
        }
        Assert.Equal(0L, pool.InUseBytes);
    }

    [Fact]
    public void DestinationFailuresPropagateUnchanged()
    {
        using JsonDocument document = JsonDocument.Parse("null");
        InvalidOperationException failure = new("Destination failure.");
        ThrowingWriter destination = new(failure);
        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => new UnsafeJcsCanonicalizer().Canonicalize(document.RootElement, destination)));
    }

    [Fact]
    public void SharedCanonicalizerSupportsIndependentConcurrentCalls()
    {
        IJsonCanonicalizer canonicalizer = new UnsafeJcsCanonicalizer();
        Parallel.For(0, 32, index =>
        {
            using JsonDocument document = JsonDocument.Parse("{\"b\":2,\"a\":" + index + "}");
            ArrayBufferWriter<byte> destination = new();
            canonicalizer.Canonicalize(document.RootElement, destination);
            Assert.Equal("{\"a\":" + index + ",\"b\":2}", Encoding.UTF8.GetString(destination.WrittenSpan));
        });
    }

    private static string Canonicalize(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        ValidateInput(document.RootElement);
        ArrayBufferWriter<byte> destination = new();
        IJsonCanonicalizer canonicalizer = new UnsafeJcsCanonicalizer();
        canonicalizer.ValidateInput(document.RootElement);
        canonicalizer.Canonicalize(document.RootElement, destination);
        return Encoding.UTF8.GetString(destination.WrittenSpan);
    }

    private static void AssertRejected(JsonElement value)
    {
        JsonException validationFailure = Assert.Throws<JsonException>(() => ValidateInput(value));
        using BorrowedWriter destination = new();
        IJsonCanonicalizer canonicalizer = new UnsafeJcsCanonicalizer();
        JsonException publicValidationFailure = Assert.Throws<JsonException>(() => canonicalizer.ValidateInput(value));
        JsonException canonicalizationFailure = Assert.Throws<JsonException>(() => canonicalizer.Canonicalize(value, destination));
        Assert.Equal(0, destination.RequestCount);
        Assert.Equal(string.Empty, destination.Text);
        Assert.False(destination.IsDisposed);
        foreach (JsonException failure in new[] { validationFailure, publicValidationFailure, canonicalizationFailure })
        {
            Assert.Null(failure.InnerException);
            Assert.DoesNotContain("sensitive-property", failure.ToString());
            Assert.DoesNotContain("sensitive-value", failure.ToString());
            Assert.Null(failure.Path);
        }
    }

    private static string Nest(int levels, bool objects, string leaf)
    {
        string result = leaf;
        for (int level = 0; level < levels; level++)
            result = objects ? "{\"x\":" + result + "}" : "[" + result + "]";
        return result;
    }

    private static byte[] Join(string prefix, byte[] bytes, string suffix) =>
        [.. Encoding.UTF8.GetBytes(prefix), .. bytes, .. Encoding.UTF8.GetBytes(suffix)];

    private sealed class BorrowedWriter : IBufferWriter<byte>, IDisposable
    {
        private readonly ArrayBufferWriter<byte> buffer = new();
        private readonly int callingThread = Environment.CurrentManagedThreadId;
        public bool IsDisposed { get; private set; }
        public int RequestCount { get; private set; }
        public string Text => Encoding.UTF8.GetString(buffer.WrittenSpan);

        public void Advance(int count) => buffer.Advance(count);
        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            CheckBorrow();
            return buffer.GetMemory(sizeHint);
        }
        public Span<byte> GetSpan(int sizeHint = 0)
        {
            CheckBorrow();
            return buffer.GetSpan(sizeHint);
        }
        private void CheckBorrow()
        {
            Assert.False(IsDisposed);
            Assert.Equal(callingThread, Environment.CurrentManagedThreadId);
            RequestCount++;
        }
        public void Dispose() => IsDisposed = true;
    }

    private sealed class ThrowingWriter(Exception failure) : IBufferWriter<byte>
    {
        public void Advance(int count) => throw failure;
        public Memory<byte> GetMemory(int sizeHint = 0) => throw failure;
        public Span<byte> GetSpan(int sizeHint = 0) => throw failure;
    }
}