using AuthSystem.Api.Models;

namespace AuthSystem.Api.Services;

public record GeneratedRefreshToken(string RawToken, string Hash, DateTime ExpiresAtUtc);

public interface ITokenService
{
    (string AccessToken, DateTime ExpiresAtUtc) GenerateAccessToken(
        ApplicationUser user, ClientApplication application, IList<string> roles);

    GeneratedRefreshToken GenerateRefreshToken();
    string HashRefreshToken(string rawToken);
}
