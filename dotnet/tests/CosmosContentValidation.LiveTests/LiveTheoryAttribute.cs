using Xunit;

namespace CosmosContentValidation.LiveTests;

/// <summary>Discovery-time opt-in; missing configuration is a failure once enabled.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class LiveTheoryAttribute : TheoryAttribute
{
    public LiveTheoryAttribute()
    {
        if (!IsEnabled)
            Skip = "Live Azure tests require the exact opt-in COSMOS_RUN_LIVE_TESTS=1.";
    }

    internal static bool IsEnabled => string.Equals(
        Environment.GetEnvironmentVariable("COSMOS_RUN_LIVE_TESTS"), "1", StringComparison.Ordinal);
}