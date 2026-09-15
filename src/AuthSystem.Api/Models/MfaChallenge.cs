namespace AuthSystem.Api.Models;

/// A pending two-factor login, issued by /api/auth/login and redeemed by
/// /api/auth/login/2fa. Stored in the database rather than in process memory so any
/// instance can redeem a challenge created by any other one.
public class MfaChallenge
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// SHA-256 of the token handed to the client. The raw token is never stored, so a
    /// database leak does not let anyone complete a pending 2FA login.
    public string TokenHash { get; set; } = null!;

    public Guid UserId { get; set; }

    /// Client the login was started for, so the redeemed token is scoped to the same
    /// application the user was logging into.
    public Guid ClientApplicationId { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
}
