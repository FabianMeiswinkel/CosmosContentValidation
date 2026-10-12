using System.Reflection;
using System.Xml.Linq;
using CosmosContentValidation.Sample.Providers;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class ArchitectureTests
{
    private const string SampleAssemblyName = "CosmosContentValidation.Sample";
    private const string ProviderNamespace = "CosmosContentValidation.Sample.Providers";
    private static readonly Type[] ProviderContracts =
    [
        typeof(IJsonCanonicalizer), typeof(IContentHasher), typeof(IContentSigner),
        typeof(IContentVerifier), typeof(IVerificationKeyResolver)
    ];

    [Fact]
    public void LibraryAssemblyDoesNotReferenceCryptographyCanonicalizationOrSampleAssemblies()
    {
        Assembly library = typeof(ContentValidationProcessor).Assembly;
        Assert.Equal("CosmosContentValidation", library.GetName().Name);

        // Inspect the actual emitted references, including any introduced by exception types.
        // Do not exclude a disallowed reference just because no crypto operation calls it.
        Assert.DoesNotContain(library.GetReferencedAssemblies(), reference =>
            reference.Name is { } name &&
            (name.StartsWith("System.Security.Cryptography", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("System.Formats.Asn1", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("Jcs.Net", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith(SampleAssemblyName, StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void LibraryDefinesProviderContractsButNoConcreteProviderImplementations()
    {
        Assembly library = typeof(ContentValidationProcessor).Assembly;
        Assert.All(ProviderContracts, contract =>
        {
            Assert.True(contract.IsInterface);
            Assert.Same(library, contract.Assembly);
        });
        // GetTypes, not GetExportedTypes: internal implementations would violate the boundary too.
        Assert.DoesNotContain(library.GetTypes(), IsConcreteProvider);
    }

    [Fact]
    public void AllFiveSampleProvidersAreConcreteUnsafeImplementationsInTheExactSampleAssembly()
    {
        Assembly sample = typeof(UnsafeJcsCanonicalizer).Assembly;
        Assert.Equal(SampleAssemblyName, sample.GetName().Name);
        Assert.NotSame(typeof(ContentValidationProcessor).Assembly, sample);
        (Type Contract, Type Provider)[] expected =
        [
            (typeof(IJsonCanonicalizer), typeof(UnsafeJcsCanonicalizer)),
            (typeof(IContentHasher), typeof(UnsafeSha256ContentHasher)),
            (typeof(IContentSigner), typeof(UnsafeEcdsaContentSigner)),
            (typeof(IContentVerifier), typeof(UnsafeEcdsaContentVerifier)),
            (typeof(IVerificationKeyResolver), typeof(UnsafeInMemoryVerificationKeyResolver))
        ];

        Type[] implementations = sample.GetTypes().Where(IsConcreteProvider).ToArray();
        Assert.Equal(expected.Select(pair => pair.Provider).OrderBy(type => type.FullName, StringComparer.Ordinal),
            implementations.OrderBy(type => type.FullName, StringComparer.Ordinal));
        Assert.All(expected, pair =>
        {
            Assert.True(pair.Contract.IsAssignableFrom(pair.Provider));
            Assert.Same(sample, pair.Provider.Assembly);
            Assert.Equal(SampleAssemblyName, pair.Provider.Assembly.GetName().Name);
        });
        Assert.All(implementations, type =>
        {
            Assert.True(type.IsClass);
            Assert.True(type.IsPublic);
            Assert.False(type.IsAbstract);
            Assert.StartsWith("Unsafe", type.Name);
            Assert.Equal(ProviderNamespace, type.Namespace);
            Assert.Same(sample, type.Assembly);
        });
    }

    [Fact]
    public void OriginalLibraryProjectHasNoCanonicalizationCryptoPackagesOrSampleProjectReference()
    {
        // Read the original manifest rather than a copied or filtered dependency list.
        XDocument project = XDocument.Load(FindLibraryProject());
        string[] packages = project.Descendants()
            .Where(element => element.Name.LocalName == "PackageReference")
            .SelectMany(ReferenceNames).ToArray();
        Assert.DoesNotContain(packages, name =>
            name.Contains("Jcs", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Crypto", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Asn1", StringComparison.OrdinalIgnoreCase)
                || name.Contains("BouncyCastle", StringComparison.OrdinalIgnoreCase));

        string[] projects = project.Descendants()
            .Where(element => element.Name.LocalName == "ProjectReference")
            .SelectMany(ReferenceNames).ToArray();
        Assert.DoesNotContain(projects, name => name.Contains(SampleAssemblyName, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void OriginalProviderDirectoryContainsNoFiles()
    {
        string directory = Path.Combine(Path.GetDirectoryName(FindLibraryProject())!, "Providers");
        if (Directory.Exists(directory)) Assert.Empty(Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories));
    }

    private static bool IsConcreteProvider(Type type) =>
        !type.IsInterface && !type.IsAbstract && ProviderContracts.Any(contract => contract.IsAssignableFrom(type));

    private static IEnumerable<string> ReferenceNames(XElement element) => element.Attributes()
        .Where(attribute => attribute.Name.LocalName is "Include" or "Update")
        .SelectMany(attribute => attribute.Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    private static string FindLibraryProject()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "dotnet", "src", "CosmosContentValidation", "CosmosContentValidation.csproj");
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException("Architecture tests must run from the checkout so the original library project can be inspected.");
    }
}