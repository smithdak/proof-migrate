using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProofMigrate.SitecoreExtractor;

internal static class Program
{
    private const long MaxInputBytes = 256L * 1024L * 1024L;
    private const string ExpectedApiVersion = "proof-migrate.dev/sitecore-export/v1";
    private static readonly HashSet<string> ForbiddenPropertyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "password",
        "secret",
        "token",
        "connectionstring",
        "connection_string",
        "privatekey",
        "private_key"
    };

    public static int Main(string[] args)
    {
        try
        {
            PackageArguments options = ParseArguments(args);
            Package(options);
            return 0;
        }
        catch (Exception error) when (error is ArgumentException or IOException or JsonException or InvalidOperationException)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static PackageArguments ParseArguments(string[] args)
    {
        if (args.Length != 5 || !string.Equals(args[0], "package", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "usage: proof-migrate-sitecore-extractor package --input <sitecore-export.json> --output <new-directory>");
        }

        string? input = null;
        string? output = null;
        for (int index = 1; index < args.Length; index += 2)
        {
            switch (args[index])
            {
                case "--input":
                    input = args[index + 1];
                    break;
                case "--output":
                    output = args[index + 1];
                    break;
                default:
                    throw new ArgumentException($"unknown argument: {args[index]}");
            }
        }

        if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(output))
        {
            throw new ArgumentException("both --input and --output are required");
        }

        return new PackageArguments(Path.GetFullPath(input), Path.GetFullPath(output));
    }

    private static void Package(PackageArguments options)
    {
        FileInfo source = new(options.Input);
        if (!source.Exists)
        {
            throw new IOException($"input file does not exist: {source.FullName}");
        }
        if (source.Length > MaxInputBytes)
        {
            throw new IOException($"input exceeds the {MaxInputBytes} byte safety limit");
        }
        if (Directory.Exists(options.Output) || File.Exists(options.Output))
        {
            throw new IOException($"output already exists and will not be overwritten: {options.Output}");
        }

        byte[] sourceBytes = File.ReadAllBytes(source.FullName);
        using JsonDocument document = JsonDocument.Parse(sourceBytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 128
        });
        ValidateRoot(document.RootElement);
        RejectForbiddenProperties(document.RootElement, "$", 0);

        string outputParent = Directory.GetParent(options.Output)?.FullName
            ?? throw new IOException("output must have a parent directory");
        Directory.CreateDirectory(outputParent);
        string staging = Path.Combine(outputParent, $".proof-migrate-extractor-{Guid.NewGuid():N}");
        Directory.CreateDirectory(staging);
        try
        {
            string exportName = "source-export.json";
            File.WriteAllBytes(Path.Combine(staging, exportName), sourceBytes);
            string sha256 = Convert.ToHexString(SHA256.HashData(sourceBytes)).ToLowerInvariant();
            ExtractorManifest manifest = new(
                "proof-migrate.dev/extractor-manifest/v1",
                exportName,
                sourceBytes.LongLength,
                $"sha256:{sha256}",
                true,
                false,
                false,
                [
                    "This slice packages an already-authorized offline export.",
                    "Native Sitecore API capture remains unavailable until the estate version and acquisition boundary are known."
                ]);
            byte[] manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
            File.WriteAllBytes(Path.Combine(staging, "extractor-manifest.json"), manifestBytes);
            Directory.Move(staging, options.Output);
        }
        catch
        {
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, true);
            }
            throw;
        }
    }

    private static void ValidateRoot(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("api_version", out JsonElement apiVersion)
            || !string.Equals(apiVersion.GetString(), ExpectedApiVersion, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"input must use api_version {ExpectedApiVersion}");
        }
        if (!root.TryGetProperty("source", out JsonElement source)
            || !source.TryGetProperty("extraction", out JsonElement extraction)
            || !extraction.TryGetProperty("read_only", out JsonElement readOnly)
            || readOnly.ValueKind != JsonValueKind.True)
        {
            throw new InvalidOperationException("input must declare source.extraction.read_only as true");
        }
    }

    private static void RejectForbiddenProperties(JsonElement element, string path, int depth)
    {
        if (depth > 128)
        {
            throw new InvalidOperationException("input JSON exceeded the supported nesting depth");
        }
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (ForbiddenPropertyNames.Contains(property.Name))
                {
                    throw new InvalidOperationException($"forbidden secret-bearing property at {path}.{property.Name}");
                }
                RejectForbiddenProperties(property.Value, $"{path}.{property.Name}", depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            int index = 0;
            foreach (JsonElement child in element.EnumerateArray())
            {
                RejectForbiddenProperties(child, $"{path}[{index}]", depth + 1);
                index++;
            }
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private sealed record PackageArguments(string Input, string Output);

    private sealed record ExtractorManifest(
        string ApiVersion,
        string ExportFile,
        long ByteLength,
        string SourceDigest,
        bool ReadOnlySource,
        bool NetworkAccess,
        bool NativeSitecoreApi,
        string[] Limitations);
}

