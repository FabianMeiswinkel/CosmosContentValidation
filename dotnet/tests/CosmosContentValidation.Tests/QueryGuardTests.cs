using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class QueryGuardTests
{
    [Theory]
    [InlineData("SELECT * FROM c")]
    [InlineData("  select\t*\r\nfrom\fc")]
    [InlineData("SELECT * FROM root r")]
    [InlineData("SELECT * FROM root AS r WHERE r.id = @id")]
    [InlineData("SELECT * FROM c WHERE c.id = @id")]
    [InlineData("SELECT * FROM c ORDER BY c.value")]
    public void CompleteDocumentPrefixIsAccepted(string query)
    {
        ContentValidationQueryGuard.Validate(query);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t\r\n\f")]
    [InlineData("\uFEFFSELECT * FROM c")]
    [InlineData("-- comment\nSELECT * FROM c")]
    [InlineData("/* comment */ SELECT * FROM c")]
    [InlineData("SELECT* FROM c")]
    [InlineData("SELECT *FROM c")]
    [InlineData("SELECT * FROM")]
    [InlineData("SELECT * FROM \t")]
    [InlineData("SELECT * FROMRoot")]
    [InlineData("SELECT * FROM(c)")]
    [InlineData("SELECT * FROM (SELECT * FROM c) root")]
    [InlineData("SELECT * FROM c JOIN child IN c.children")]
    [InlineData("SELECT * FROM child IN c.children")]
    [InlineData("SELECT * FROM c, d")]
    [InlineData("SELECT * FROM c AS root JOIN child IN root.children")]
    [InlineData("SELECT c FROM c")]
    [InlineData("SELECT VALUE c FROM c")]
    [InlineData("SELECT DISTINCT * FROM c")]
    [InlineData("SELECT TOP 1 * FROM c")]
    [InlineData("SELECT * INTO x FROM c")]
    [InlineData("\u00A0SELECT * FROM c")]
    public void AnythingOutsideStrictPrefixIsRejected(string? query)
    {
        ContentValidationException failure = Assert.Throws<ContentValidationException>(
            () => ContentValidationQueryGuard.Validate(query));
        Assert.Equal(ContentValidationFailure.UnsupportedOperation, failure.Failure);
    }
}
