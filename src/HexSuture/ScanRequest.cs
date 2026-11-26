namespace HexSuture;

internal sealed record ScanRequest(
    string Id,
    string Device,
    string Kind,
    string? Folder,
    string RequestedUtc,
    string? EngineVersion,
    string? SignatureVersion,
    string? EndedUtc,
    int? ExitCode,
    string? Error);
