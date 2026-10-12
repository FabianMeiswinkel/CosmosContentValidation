using System.Net;
using Microsoft.Azure.Cosmos;

namespace CosmosContentValidation;

/// <summary>Delegates virtual response metadata while owning validated content and the native response.</summary>
/// <remarks>
/// Cosmos 3.63.2 query responses can synthesize Content in an override and ignore replacement through
/// the base setter. This facade is therefore required for validated replay. IndexMetrics is nonvirtual;
/// stream queries requesting it or query advice are rejected before native iterator construction.
/// </remarks>
internal sealed class ContentValidationResponseMessage : ResponseMessage
{
    private readonly ResponseMessage original;
    private Stream? nativeContent;
    private Stream? content;
    private int disposed;

    internal ContentValidationResponseMessage(ResponseMessage original, Stream nativeContent, Stream content)
    {
        this.original = original ?? throw new ArgumentNullException(nameof(original));
        this.nativeContent = nativeContent ?? throw new ArgumentNullException(nameof(nativeContent));
        this.content = content ?? throw new ArgumentNullException(nameof(content));
    }

    public override HttpStatusCode StatusCode => original.StatusCode;
    public override Headers Headers => original.Headers;
    public override string ContinuationToken => original.ContinuationToken;
    public override string ErrorMessage => original.ErrorMessage;
    public override RequestMessage RequestMessage => original.RequestMessage;
    public override bool IsSuccessStatusCode => original.IsSuccessStatusCode;

    public override CosmosDiagnostics Diagnostics
    {
        get => original.Diagnostics;
        set => original.Diagnostics = value;
    }

    public override Stream Content
    {
        get => content!;
        set
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            if (ReferenceEquals(content, value)) return;
            Stream? previous = content;
            content = value;
            previous?.Dispose();
        }
    }

    public override ResponseMessage EnsureSuccessStatusCode()
    {
        original.EnsureSuccessStatusCode();
        return this;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref disposed, 1) == 0)
        {
            Stream? owned = content;
            Stream? native = nativeContent;
            content = null;
            nativeContent = null;
            try
            {
                native?.Dispose();
            }
            finally
            {
                try
                {
                    owned?.Dispose();
                }
                finally
                {
                    original.Dispose();
                }
            }
        }
    }
}
