using AuthSystem.Api.Models;

namespace AuthSystem.Api.Services;

public interface IClientApplicationService
{
    Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken ct = default);

    /// Audiences currently accepted, read from an in-memory snapshot. Synchronous by
    /// design: it is called from the bearer handler's audience validator, which has no
    /// async path, and must never become a database round trip per request.
    IReadOnlyCollection<string> GetActiveAudiences();

    /// Reloads the snapshot. Called once at startup and whenever an application is
    /// registered or changed.
    Task RefreshAsync(CancellationToken ct = default);
}
