using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Api.Dtos;

public record RegisterRequest(
    [Required, EmailAddress] string Email,
    [Required, MinLength(8)] string Password
);

public record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required] string Password
);

public record TwoFactorLoginRequest(
    [Required] string MfaToken,
    [Required, StringLength(6, MinimumLength = 6)] string Code
);

public record RefreshRequest([Required] string RefreshToken);

public record LogoutRequest([Required] string RefreshToken);

public record TwoFactorEnableRequest(
    [Required, StringLength(6, MinimumLength = 6)] string Code
);

public record TwoFactorDisableRequest(
    [Required, StringLength(6, MinimumLength = 6)] string Code
);

public record TokenResponse(string AccessToken, string RefreshToken, DateTime AccessTokenExpiresAtUtc);

public record LoginResponse(bool RequiresTwoFactor, string? MfaToken, TokenResponse? Tokens);

public record TwoFactorSetupResponse(string SharedKey, string AuthenticatorUri);

public record UserResponse(Guid Id, string Email, bool TwoFactorEnabled, IList<string> Roles);
