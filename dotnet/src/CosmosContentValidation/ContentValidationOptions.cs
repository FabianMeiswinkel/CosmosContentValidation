namespace CosmosContentValidation;

/// <summary>Configuration is copied and validated by ContentValidationProcessor at construction.</summary>
public sealed class ContentValidationOptions
{
    /// <summary>Exact case-sensitive root names, added to the five service-owned defaults.</summary>
    public IReadOnlyCollection<string> AdditionalIgnoredRootProperties { get; init; } = Array.Empty<string>();

    /// <summary>Actual container partition-key paths. Their root properties cannot be ignored.</summary>
    public IReadOnlyList<string> PartitionKeyPaths { get; init; } = new[] { "/pk" };

    /// <summary>Maximum signed wire document size, including the signature envelope.</summary>
    public int MaxDocumentBytes { get; init; } = 2 * 1024 * 1024;

    /// <summary>Maximum buffered JSON input or intermediate representation.</summary>
    public int MaxBufferedBytes { get; init; } = 8 * 1024 * 1024;
}