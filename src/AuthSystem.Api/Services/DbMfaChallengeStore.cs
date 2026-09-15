using System.Security.Cryptography;
using System.Text;
using AuthSystem.Api.Data;
using AuthSystem.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Api.Services;

/// Database-backed pending-2FA store. Replaces the previous IMemoryCache version,
/// which made the service single-instance: a challenge created on one instance was
/// invisible to every other one, so a load-balanced 2FA login failed intermittently.
public class DbMfaChallengeStore(AppDbContext db) : IMfaChallengeStore
{
    public async Task<string> CreateChallengeAsync(
        Guid userId, Guid clientApplicationId, TimeSpan ttl, CancellationToken ct = default)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        db.MfaChallenges.Add(new MfaChallenge
        {
            TokenHash = HashToken(rawToken),
            UserId = userId,
            ClientApplicationId = clientApplicationId,
            ExpiresAtUtc = DateTime.UtcNow.AddTicks(ttl.Ticks),
        });
        await db.SaveChangesAsync(ct);

        return rawToken;
    }

    public async Task<MfaChallengeResult?> ConsumeChallengeAsync(string mfaToken, CancellationToken ct = default)
    {
        var hash = HashToken(mfaToken);

        // DELETE ... RETURNING makes the read and the delete one atomic statement, so two
        // instances racing on the same mfaToken cannot both redeem it: exactly one gets a
        // row back. Doing this as SELECT-then-DELETE would leave that race open.
        var redeemed = await db.Database
            .SqlQuery<MfaChallengeRow>($"""
                DELETE FROM "MfaChallenges"
                WHERE "TokenHash" = {hash} AND "ExpiresAtUtc" > NOW()
                RETURNING "UserId", "ClientApplicationId"
                """)
            .ToListAsync(ct);

        if (redeemed.Count == 0)
        {
            return null;
        }

        return new MfaChallengeResult(redeemed[0].UserId, redeemed[0].ClientApplicationId);
    }

    /// Best-effort cleanup of challenges nobody redeemed. They are already unusable once
    /// expired; this only keeps the table from growing without bound.
    public async Task<int> RemoveExpiredAsync(CancellationToken ct = default) =>
        await db.MfaChallenges.Where(c => c.ExpiresAtUtc <= DateTime.UtcNow).ExecuteDeleteAsync(ct);

    private static string HashToken(string rawToken) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));

    private record MfaChallengeRow(Guid UserId, Guid ClientApplicationId);
}
