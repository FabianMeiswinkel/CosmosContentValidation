using System.Formats.Asn1;
using System.Security.Cryptography;

namespace CosmosContentValidation.Sample.Providers;

/// <summary>Shared implementation detail; no additional public key-loading surface.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// </remarks>
internal static class UnsafeEcdsaKeyImport
{
    internal const string AlgorithmId = "ECDSA-P256-SHA256-P1363";
    internal const int HashSizeInBytes = 32;
    internal const int SignatureSizeInBytes = 64;
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string P256Oid = "1.2.840.10045.3.1.7";

    internal static ECDsa Import(string pem, bool privateKey, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem, parameterName);
        ReadOnlySpan<char> text = pem.AsSpan().Trim();
        string label = privateKey ? "PRIVATE KEY" : "PUBLIC KEY";

        // ImportFromPem deliberately skips unknown/malformed blocks. Do not allow
        // that permissiveness to select one key from ambiguous or mixed input.
        if (!PemEncoding.TryFind(text, out PemFields fields)
            || fields.Location.GetOffsetAndLength(text.Length) != (0, text.Length)
            || !text[fields.Label].SequenceEqual(label.AsSpan()))
        {
            throw new ArgumentException($"Expected exactly one {label} PEM block, surrounded only by whitespace.", parameterName);
        }

        byte[] der = new byte[fields.DecodedDataLength];
        try
        {
            if (!Convert.TryFromBase64Chars(text[fields.Base64Data], der, out int written) || written != der.Length)
                throw new ArgumentException("Invalid PEM encoding.", parameterName);

            ValidateAlgorithm(der, privateKey);
            ECDsa key = ECDsa.Create();
            try
            {
                int bytesRead;
                if (privateKey)
                    key.ImportPkcs8PrivateKey(der, out bytesRead);
                else
                    key.ImportSubjectPublicKeyInfo(der, out bytesRead);

                if (bytesRead != der.Length)
                    throw new CryptographicException("Unexpected trailing key data.");

                ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
                if (key.KeySize != 256 || !parameters.Curve.IsNamed || parameters.Curve.Oid.Value != P256Oid)
                    throw new CryptographicException("Only the named NIST P-256 curve is supported.");

                return key;
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }
        finally
        {
            // The caller owns the immutable PEM string; never retain it. Clear our
            // decoded copy, including on failed private-key imports.
            CryptographicOperations.ZeroMemory(der);
        }
    }

    private static void ValidateAlgorithm(ReadOnlyMemory<byte> der, bool privateKey)
    {
        try
        {
            AsnReader reader = new(der, AsnEncodingRules.DER);
            AsnReader keyInfo = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            if (privateKey && keyInfo.ReadInteger() != 0)
                throw new CryptographicException("Expected PKCS#8 PrivateKeyInfo version zero.");

            AsnReader algorithm = keyInfo.ReadSequence();
            if (algorithm.ReadObjectIdentifier() != EcPublicKeyOid || algorithm.ReadObjectIdentifier() != P256Oid)
                throw new CryptographicException("Only id-ecPublicKey with the named NIST P-256 curve is supported.");

            algorithm.ThrowIfNotEmpty();
            // Validate the encoded OIDs before import: some platform providers can
            // normalize explicit parameters to a named curve. Size alone is unsafe.
            // The platform importer validates the remaining key structure and point.
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("Invalid key encoding; expected a named NIST P-256 key.", exception);
        }
    }
}