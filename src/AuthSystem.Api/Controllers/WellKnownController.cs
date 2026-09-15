using AuthSystem.Api.Options;
using AuthSystem.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthSystem.Api.Controllers;

/// Public discovery documents. Anonymous by design: a consuming API has no token yet
/// when it fetches these, and they contain only public key material.
[ApiController]
[AllowAnonymous]
[Route(".well-known")]
public class WellKnownController(
    IJwtKeyProvider keyProvider,
    IOptions<JwtOptions> jwtOptions
) : ControllerBase
{
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;

    /// The public half of the signing key (RFC 7517). Consumers fetch this instead of
    /// being handed a key by hand, so a rotation does not require touching every repo.
    [HttpGet("jwks.json")]
    public ActionResult<JwksDocument> Jwks()
    {
        var jwks = keyProvider.BuildJwks();
        if (jwks is null)
        {
            // Signing with HS256: there is no public key to hand out, and publishing the
            // symmetric one would let any reader mint tokens.
            return NotFound(new { message = "No hay clave pública publicable: el servicio está firmando con HS256." });
        }

        // Cacheable: the key changes only on rotation, and consumers should not hit this
        // on every request they validate.
        Response.Headers.CacheControl = "public, max-age=3600";
        return Ok(jwks);
    }

    /// Minimal OIDC-style discovery document, enough for a .NET consumer to point
    /// AddJwtBearer at an Authority and configure nothing else by hand.
    [HttpGet("openid-configuration")]
    public IActionResult OpenIdConfiguration()
    {
        var issuerUrl = $"{Request.Scheme}://{Request.Host}";

        Response.Headers.CacheControl = "public, max-age=3600";
        return Ok(new Dictionary<string, object>
        {
            ["issuer"] = _jwtOptions.Issuer,
            ["jwks_uri"] = $"{issuerUrl}/.well-known/jwks.json",
            ["id_token_signing_alg_values_supported"] = keyProvider.ValidAlgorithms,
            ["token_endpoint"] = $"{issuerUrl}/api/auth/login",
            ["grant_types_supported"] = new[] { "password", "refresh_token" },
        });
    }
}
