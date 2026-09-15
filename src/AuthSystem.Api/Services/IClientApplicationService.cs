using AuthSystem.Api.Models;

namespace AuthSystem.Api.Services;

public interface IClientApplicationService
{
    Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken ct = default);

    /// Audiences currently accepted, read from an in-memory snapshot. Synchronous by
    /// design: it is called from the bearer handler's audience validator, which has no
    /// async path, and must never become a database round trip per request.
    IReadOnlyCollection<string> GetActiveAudiences();

    /// Audience of the default application, which is the one that governs the service
    /// itself. Holding Admin in any other application must not grant administration of
    /// the registry.
    string? GetSystemAudience();

    /// Reloads the snapshot. Called once at startup and whenever an application is
    /// registered or changed.
    Task RefreshAsync(CancellationToken ct = default);
}
