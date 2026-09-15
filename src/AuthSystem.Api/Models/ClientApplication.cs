namespace AuthSystem.Api.Models;

/// A consuming application. Each one gets its own audience, so a token minted for one
/// app is rejected by every other: a token leaked from the least careful consumer does
/// not open the rest.
public class ClientApplication
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// Stable public identifier the client sends at login (e.g. "finance-api").
    public string ClientId { get; set; } = null!;

    /// Value placed in the token's `aud` claim, and the only audience this app accepts.
    public string Audience { get; set; } = null!;

    public string DisplayName { get; set; } = null!;

    /// Turning this off stops new tokens being issued for the app and makes existing
    /// ones fail audience validation, without deleting its roles or history.
    public bool IsActive { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
