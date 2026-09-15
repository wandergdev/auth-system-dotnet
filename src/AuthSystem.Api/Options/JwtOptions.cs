namespace AuthSystem.Api.Options;

public class JwtOptions
{
    public const string SectionName = "Jwt";

    /// Signing algorithm: "RS256" (asymmetric, default) or "HS256" (legacy, symmetric).
    public string Algorithm { get; set; } = "RS256";

    /// RSA private key used with RS256, as a PKCS#8 PEM block or the base64 of its DER
    /// encoding. Never committed: user-secrets locally, Jwt__PrivateKey in deployment.
    public string? PrivateKey { get; set; }

    /// Public half of the key being retired, published alongside the current one during
    /// a rotation. Tokens it signed stay valid until they expire, and consumers that
    /// cached the old JWKS keep working. Accepts a PEM public key or its base64.
    public string? PreviousPublicKey { get; set; }

    /// Symmetric key used with HS256. Still read while RS256 is signing, to keep
    /// validating tokens issued before the switch. See AcceptLegacyHs256.
    public string? Secret { get; set; }

    /// Keep accepting HS256-signed tokens while running on RS256. Turn off once no
    /// token issued before the switch can still be within its lifetime.
    public bool AcceptLegacyHs256 { get; set; } = true;

    public string Issuer { get; set; } = null!;
    public int AccessTokenMinutes { get; set; } = 15;
    public int RefreshTokenDays { get; set; } = 7;
    public int MfaChallengeMinutes { get; set; } = 5;
}
