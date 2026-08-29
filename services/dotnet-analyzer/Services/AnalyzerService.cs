// .NET/C# binary analyzer.
// Uses System.Reflection.Metadata (the same low-level library .NET's own
// tooling is built on) to read PE headers and, if present, the CLR/.NET
// metadata tables directly — module name, referenced assemblies, and
// type/method names — without needing to load or execute the assembly.
//
// ELF support: .NET 5+ Linux single-file binaries are a native ELF apphost
// with the managed PE DLLs appended/embedded after it. We scan the raw bytes
// for embedded MZ+PE signatures and attempt PEReader on each candidate until
// one yields CLR metadata.

using Grpc.Core;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace Malwarelab;

public class AnalyzerService : Analyzer.AnalyzerBase
{
    private const string ServiceName = "dotnet-analyzer";

    public override Task<AnalysisResult> Analyze(SampleRequest request, ServerCallContext context)
    {
        Console.WriteLine($"received sample path={request.SamplePath}");

        var result = new AnalysisResult { AnalyzerName = ServiceName };

        if (!File.Exists(request.SamplePath))
        {
            result.Error = $"sample not found at {request.SamplePath}";
            return Task.FromResult(result);
        }

        // Read the whole file so we can scan for embedded PEs in ELF apphost binaries.
        byte[] fileBytes;
        try
        {
            fileBytes = File.ReadAllBytes(request.SamplePath);
        }
        catch (Exception ex)
        {
            result.Error = $"failed to read file: {ex.Message}";
            return Task.FromResult(result);
        }

        // Collect candidate offsets to try as PE start positions.
        // Offset 0 covers a plain PE file. Additional offsets cover embedded
        // MZ blobs inside an ELF apphost (the managed DLL(s) live there).
        var candidateOffsets = FindPECandidateOffsets(fileBytes);

        foreach (var offset in candidateOffsets)
        {
            try
            {
                using var ms = new MemoryStream(fileBytes, offset, fileBytes.Length - offset, writable: false);
                using var peReader = new PEReader(ms);

                if (!peReader.HasMetadata)
                    continue;

                var metadataReader = peReader.GetMetadataReader();
                result.Language = "dotnet";

                if (offset > 0)
                    result.Extra["embedded_pe_offset"] = $"0x{offset:X}";

                var moduleDef = metadataReader.GetModuleDefinition();
                result.Extra["module_name"] = metadataReader.GetString(moduleDef.Name);

                var assemblyRefs = new List<string>();
                foreach (var handle in metadataReader.AssemblyReferences)
                {
                    var assemblyRef = metadataReader.GetAssemblyReference(handle);
                    assemblyRefs.Add(metadataReader.GetString(assemblyRef.Name));
                }
                result.Extra["referenced_assembly_count"] = assemblyRefs.Count.ToString();
                if (assemblyRefs.Count > 0)
                    result.Extra["referenced_assemblies"] = string.Join(",", assemblyRefs.Take(15));

                var typeNames = new List<string>();
                foreach (var handle in metadataReader.TypeDefinitions)
                {
                    var typeDef = metadataReader.GetTypeDefinition(handle);
                    var name = metadataReader.GetString(typeDef.Name);
                    if (name != "<Module>")
                        typeNames.Add(name);
                    if (typeNames.Count >= 20) break;
                }
                result.Extra["type_count_sampled"] = typeNames.Count.ToString();
                if (typeNames.Count > 0)
                    result.Extra["sample_type_names"] = string.Join(",", typeNames);

                Console.WriteLine($"dotnet analysis complete: offset=0x{offset:X} module={result.Extra["module_name"]} refs={assemblyRefs.Count} types_sampled={typeNames.Count}");
                return Task.FromResult(result);
            }
            catch
            {
                // This candidate didn't parse as a valid .NET PE — try the next one.
            }
        }

        // Nothing yielded CLR metadata.
        result.Language = "unknown";
        result.Extra["note"] = "no CLR metadata found (not a .NET assembly, or embedded PE not located)";
        return Task.FromResult(result);
    }

    /// <summary>
    /// Returns a list of byte offsets to try as PE candidates.
    /// Always includes offset 0. For ELF files, also scans for embedded MZ headers
    /// that are backed by a valid PE signature ("PE\0\0" at MZ offset 0x3C).
    /// Candidates are de-duplicated and sorted ascending so we try offset 0 first.
    /// </summary>
    private static List<int> FindPECandidateOffsets(byte[] data)
    {
        var offsets = new HashSet<int> { 0 };

        // Only bother scanning if this looks like an ELF (not already a PE).
        bool isElf = data.Length >= 4 &&
                     data[0] == 0x7F && data[1] == (byte)'E' &&
                     data[2] == (byte)'L' && data[3] == (byte)'F';

        if (isElf)
        {
            // Scan for MZ signatures. For each one, validate there's a PE header
            // at the offset stored in the DOS header at +0x3C.
            for (int i = 0; i < data.Length - 4; i++)
            {
                if (data[i] == 0x4D && data[i + 1] == 0x5A) // "MZ"
                {
                    // Read the PE header offset from the DOS stub (little-endian uint32 at +0x3C).
                    if (i + 0x40 <= data.Length)
                    {
                        int peOffset = BitConverter.ToInt32(data, i + 0x3C);
                        int absOffset = i + peOffset;
                        if (absOffset >= 0 && absOffset + 4 <= data.Length &&
                            data[absOffset]     == (byte)'P' &&
                            data[absOffset + 1] == (byte)'E' &&
                            data[absOffset + 2] == 0x00 &&
                            data[absOffset + 3] == 0x00)
                        {
                            offsets.Add(i);
                        }
                    }
                }
            }
        }

        var result = new List<int>(offsets);
        result.Sort();
        return result;
    }

    public override Task<CapabilitiesResponse> Capabilities(Empty request, ServerCallContext context)
    {
        var response = new CapabilitiesResponse { ServiceName = ServiceName };
        response.SupportedFormats.Add("PE");
        response.SupportedFormats.Add("ELF");
        response.SupportedLanguages.Add("dotnet");
        return Task.FromResult(response);
    }
}
