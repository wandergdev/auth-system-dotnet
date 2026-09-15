namespace AuthSystem.Api.Services;

public record MfaChallengeResult(Guid UserId, Guid ClientApplicationId);

public interface IMfaChallengeStore
{
    Task<string> CreateChallengeAsync(Guid userId, Guid clientApplicationId, TimeSpan ttl, CancellationToken ct = default);

    /// Redeems a challenge. Single use: a successful call invalidates the token, so a
    /// stolen mfaToken cannot be replayed and cannot be brute-forced for its lifetime.
    Task<MfaChallengeResult?> ConsumeChallengeAsync(string mfaToken, CancellationToken ct = default);
}
