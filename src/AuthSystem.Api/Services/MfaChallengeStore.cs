using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;

namespace AuthSystem.Api.Services;

/// In-memory pending-2FA-login store: swap for a distributed cache (Redis, DB)
/// before running more than one API instance.
public class MfaChallengeStore(IMemoryCache cache) : IMfaChallengeStore
{
    private const string KeyPrefix = "mfa-challenge:";

    public string CreateChallenge(Guid userId, TimeSpan ttl)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        cache.Set(KeyPrefix + token, userId, ttl);
        return token;
    }

    public Guid? ConsumeChallenge(string mfaToken)
    {
        var key = KeyPrefix + mfaToken;
        if (cache.TryGetValue(key, out Guid userId))
        {
            cache.Remove(key);
            return userId;
        }

        return null;
    }
}
