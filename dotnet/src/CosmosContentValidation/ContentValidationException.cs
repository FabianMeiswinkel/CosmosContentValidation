namespace CosmosContentValidation;

public enum ContentValidationFailure
{
    InvalidDocument,
    MissingSignature,
    InvalidSignature,
    UnknownKey,
    UnsupportedProfile,
    PolicyMismatch,
    ReservedProperty,
    SigningUnavailable,
    UnsupportedOperation,
    PayloadTooLarge
}

/// <summary>A local content/policy failure, distinct from service HTTP failures.</summary>
public sealed class ContentValidationException : Exception
{
    public ContentValidationException(ContentValidationFailure failure, string message, Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    public ContentValidationFailure Failure { get; }
}