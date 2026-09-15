using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthSystem.Api.Models;
using AuthSystem.Api.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthSystem.Api.Services;

public class TokenService(IOptions<JwtOptions> jwtOptions, IJwtKeyProvider keyProvider) : ITokenService
{
    private readonly JwtOptions _options = jwtOptions.Value;

    public (string AccessToken, DateTime ExpiresAtUtc) GenerateAccessToken(
        ApplicationUser user, ClientApplication application, IList<string> roles)
    {
        var expiresAtUtc = DateTime.UtcNow.AddMinutes(_options.AccessTokenMinutes);

        // ASP.NET Core's JwtBearerHandler no longer maps short claim names (sub, email) to
        // their long ClaimTypes.* equivalents by default, and UserManager/User.Identity rely
        // on the long form — so both are emitted explicitly to keep either path working.
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new(ClaimTypes.Email, user.Email ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        // Signing material comes from the key provider, which also stamps the header's
        // kid. Consumers use that kid to pick the right key out of the JWKS, which is
        // what lets a key be rotated without coordinating a deploy on both sides.
        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            // Audience is the consuming application's own, not a shared one: a token
            // minted for the CRM is rejected by finance-api and vice versa.
            audience: application.Audience,
            claims: claims,
            expires: expiresAtUtc,
            signingCredentials: keyProvider.SigningCredentials
        );

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAtUtc);
    }

    public GeneratedRefreshToken GenerateRefreshToken()
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var expiresAtUtc = DateTime.UtcNow.AddDays(_options.RefreshTokenDays);
        return new GeneratedRefreshToken(rawToken, HashRefreshToken(rawToken), expiresAtUtc);
    }

    public string HashRefreshToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes);
    }
}
