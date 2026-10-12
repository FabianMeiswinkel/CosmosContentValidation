namespace CosmosContentValidation;

/// <summary>Fail-closed prefix guard for queries that return complete documents.</summary>
internal static class ContentValidationQueryGuard
{
    internal static void Validate(string? queryText)
    {
        if (queryText is null) throw Unsupported();
        int index = 0;
        SkipWhitespace(queryText, ref index);
        if (!Consume(queryText, ref index, "SELECT") || !RequireWhitespace(queryText, ref index))
            throw Unsupported();
        SkipWhitespace(queryText, ref index);
        if (index >= queryText.Length || queryText[index++] != '*' || !RequireWhitespace(queryText, ref index))
            throw Unsupported();
        SkipWhitespace(queryText, ref index);
        if (!Consume(queryText, ref index, "FROM")) throw Unsupported();
        if (index < queryText.Length && IsIdentifierCharacter(queryText[index])) throw Unsupported();
        if (!RequireWhitespace(queryText, ref index)) throw Unsupported();
        SkipWhitespace(queryText, ref index);
        if (!ReadIdentifier(queryText, ref index)) throw Unsupported();
        if (index == queryText.Length) return;
        if (!RequireWhitespace(queryText, ref index)) throw Unsupported();
        SkipWhitespace(queryText, ref index);
        if (index == queryText.Length) return;

        string next = ReadWord(queryText, ref index);
        if (IsTail(next)) return;
        if (next.Equals("AS", StringComparison.OrdinalIgnoreCase))
        {
            if (!RequireWhitespace(queryText, ref index)) throw Unsupported();
            SkipWhitespace(queryText, ref index);
            if (!ReadIdentifier(queryText, ref index)) throw Unsupported();
        }
        else
        {
            // One ordinary alias without AS is permitted. Reserved shape-changing tokens are not.
            if (next.Length == 0 || next.Equals("JOIN", StringComparison.OrdinalIgnoreCase)
                || next.Equals("IN", StringComparison.OrdinalIgnoreCase)) throw Unsupported();
        }
        if (index == queryText.Length) return;
        if (!RequireWhitespace(queryText, ref index)) throw Unsupported();
        SkipWhitespace(queryText, ref index);
        if (index == queryText.Length) return;
        if (!IsTail(ReadWord(queryText, ref index))) throw Unsupported();
    }

    private static bool Consume(string value, ref int index, string token)
    {
        if (value.Length - index < token.Length
            || !value.AsSpan(index, token.Length).Equals(token, StringComparison.OrdinalIgnoreCase))
            return false;
        index += token.Length;
        return true;
    }

    private static bool RequireWhitespace(string value, ref int index)
    {
        if (index >= value.Length || !IsWhitespace(value[index])) return false;
        return true;
    }

    private static void SkipWhitespace(string value, ref int index)
    {
        while (index < value.Length && IsWhitespace(value[index])) index++;
    }

    private static bool IsWhitespace(char value) => value is ' ' or '\t' or '\r' or '\n' or '\f';

    private static bool IsIdentifierCharacter(char value) => char.IsAsciiLetterOrDigit(value) || value is '_' or '$';

    private static bool ReadIdentifier(string value, ref int index)
    {
        int start = index;
        if (index >= value.Length || !(char.IsAsciiLetter(value[index]) || value[index] is '_' or '$')) return false;
        while (++index < value.Length && IsIdentifierCharacter(value[index])) { }
        return index > start;
    }

    private static string ReadWord(string value, ref int index)
    {
        int start = index;
        while (index < value.Length && IsIdentifierCharacter(value[index])) index++;
        return value[start..index];
    }

    private static bool IsTail(string token) => token.Equals("WHERE", StringComparison.OrdinalIgnoreCase)
        || token.Equals("ORDER", StringComparison.OrdinalIgnoreCase)
        || token.Equals("OFFSET", StringComparison.OrdinalIgnoreCase)
        || token.Equals("LIMIT", StringComparison.OrdinalIgnoreCase);

    private static ContentValidationException Unsupported() => new(ContentValidationFailure.UnsupportedOperation,
        "Only queries beginning with SELECT * FROM and returning complete documents are supported.");
}
