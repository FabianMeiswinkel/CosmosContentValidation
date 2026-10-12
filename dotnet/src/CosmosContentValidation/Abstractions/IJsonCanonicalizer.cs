using System.Buffers;
using System.Text.Json;

namespace CosmosContentValidation;

/// <summary>Canonicalizes a JSON tree without I/O. Implementations must be thread safe.</summary>
public interface IJsonCanonicalizer
{
    /// <summary>Stable, versioned wire identifier. Never silently change its semantics.</summary>
    string ProfileId { get; }

    /// <summary>Synchronously validates the entire raw JSON tree against the structural and profile input rules.</summary>
    /// <remarks>
    /// Called before any property filtering, including for excluded subtrees. Must reject duplicate
    /// decoded property names, invalid Unicode, and unsupported numbers/depth under the declared profile.
    /// Must be thread safe, perform no I/O, and neither mutate, retain nor dispose the borrowed value.
    /// This is a separate required validation step, not a default implementation or canonicalization fallback.
    /// </remarks>
    /// <exception cref="JsonException">The input violates the declared profile. Diagnostics must not contain input data.</exception>
    void ValidateInput(JsonElement value);

    /// <summary>Writes UTF-8 to a borrowed destination. Neither argument may be retained.</summary>
    void Canonicalize(JsonElement value, IBufferWriter<byte> destination);
}