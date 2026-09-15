using AuthSystem.Api.Data;
using AuthSystem.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Api.Services;

/// Reads the client application registry and keeps the accepted-audience list in memory.
///
/// The snapshot is replaced wholesale rather than mutated, so readers always observe a
/// consistent, immutable collection with no locking. Each instance refreshes on its own
/// schedule, so registering an application propagates everywhere within the TTL without
/// any coordination between instances.
public class ClientApplicationService(
    IServiceScopeFactory scopeFactory,
    ILogger<ClientApplicationService> logger
) : IClientApplicationService
{
    private static readonly TimeSpan SnapshotTtl = TimeSpan.FromSeconds(60);
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    private volatile IReadOnlyCollection<string> _audiences = [];
    private volatile string? _systemAudience;
    private DateTime _loadedAtUtc = DateTime.MinValue;

    public async Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        return await db.ClientApplications
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive, ct);
    }

    public string? GetSystemAudience() => _systemAudience;

    public IReadOnlyCollection<string> GetActiveAudiences()
    {
        // Stale snapshot: serve the current one and refresh behind the request, so no
        // caller ever waits on the database to have a token validated.
        if (DateTime.UtcNow - _loadedAtUtc > SnapshotTtl)
        {
            _ = RefreshInBackgroundAsync();
        }

        return _audiences;
    }

    public async Task RefreshAsync(CancellationToken ct = default)
    {
        await _refreshLock.WaitAsync(ct);
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var applications = await db.ClientApplications
                .AsNoTracking()
                .Where(a => a.IsActive)
                .Select(a => new { a.ClientId, a.Audience })
                .ToListAsync(ct);

            _audiences = applications.Select(a => a.Audience).ToList().AsReadOnly();
            _systemAudience = applications
                .FirstOrDefault(a => a.ClientId == Data.DataSeeder.DefaultClientId)?.Audience;
            _loadedAtUtc = DateTime.UtcNow;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task RefreshInBackgroundAsync()
    {
        // Only one refresh at a time; the rest see the lock taken and keep the snapshot.
        if (!await _refreshLock.WaitAsync(0))
        {
            return;
        }

        _refreshLock.Release();

        try
        {
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            // Never let a background refresh failure surface as an unobserved exception:
            // the previous snapshot stays valid and the next request retries.
            logger.LogWarning(ex, "Failed to refresh the client application audience snapshot.");
        }
    }
}
