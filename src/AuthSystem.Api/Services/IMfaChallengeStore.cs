namespace AuthSystem.Api.Services;

public interface IMfaChallengeStore
{
    string CreateChallenge(Guid userId, TimeSpan ttl);
    Guid? ConsumeChallenge(string mfaToken);
}
