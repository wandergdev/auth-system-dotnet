using Microsoft.IdentityModel.Tokens;

namespace AuthSystem.Api.Services;

/// A single public key as published by the JWKS endpoint (RFC 7517).
public record JsonWebKeyDto(string Kty, string Use, string Alg, string Kid, string N, string E);

public record JwksDocument(IReadOnlyList<JsonWebKeyDto> Keys);

public interface IJwtKeyProvider
{
    /// Credentials used to sign newly issued access tokens.
    SigningCredentials SigningCredentials { get; }

    /// Every key accepted when validating an incoming token. Holds more than one
    /// only during the HS256 -> RS256 transition window.
    IReadOnlyList<SecurityKey> ValidationKeys { get; }

    /// Algorithms accepted when validating. Pinned explicitly so a token cannot
    /// choose its own algorithm (algorithm confusion).
    IReadOnlyList<string> ValidAlgorithms { get; }

    /// Public half of the signing key, for consumers. Null while signing with HS256,
    /// since a symmetric key must never be published.
    JwksDocument? BuildJwks();
}
