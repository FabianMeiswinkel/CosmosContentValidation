using System.Security.Cryptography;
using System.Text.Json;
using CosmosContentValidation.Sample;
using CosmosContentValidation.Sample.Providers;
using Microsoft.Azure.Cosmos;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class SerializerDisposalTests
{
    [Fact]
    public void ThrowingDelegateDisposeCannotOrphanSuccessfullySignedOutput()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using UnsafeEcdsaContentSigner signer = new("test", key.ExportPkcs8PrivateKeyPem());
        using UnsafeEcdsaContentVerifier verifier = new("test", key.ExportSubjectPublicKeyInfoPem());
        ContentValidationProcessor processor = UnsafeSampleProviders.CreateProcessor(new(), new UnsafeInMemoryVerificationKeyResolver([verifier]), signer);
        ContentValidationSerializer serializer = new(processor, new ThrowingDisposeSerializer());
        for (int i = 0; i < 3; i++)
        {
            Assert.Throws<IOException>(() => serializer.ToStream(new { id = "test", pk = "p" }));
            Assert.Equal(0, processor.Buffers.InUseBytes);
        }
    }

    private sealed class ThrowingDisposeSerializer : CosmosSerializer
    {
        public override T FromStream<T>(Stream stream) => throw new NotSupportedException();
        public override Stream ToStream<T>(T input) => new ThrowingDisposeStream(JsonSerializer.SerializeToUtf8Bytes(input));
    }

    private sealed class ThrowingDisposeStream(byte[] bytes) : MemoryStream(bytes)
    {
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) throw new IOException("Simulated delegate disposal failure.");
        }
    }
}