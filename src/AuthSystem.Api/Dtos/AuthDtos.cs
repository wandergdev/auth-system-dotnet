using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Api.Dtos;

/// ClientId is optional on every request that takes one: omitting it falls back to the
/// default application, so clients written before applications were modelled keep
/// working unchanged.
public record RegisterRequest(
    [Required, EmailAddress] string Email,
    [Required, MinLength(8)] string Password,
    string? ClientId = null
);

public record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required] string Password,
    string? ClientId = null
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

public record ClientApplicationResponse(string ClientId, string Audience, string DisplayName, bool IsActive);

public record CreateClientApplicationRequest(
    [Required, StringLength(128, MinimumLength = 2)] string ClientId,
    [Required, StringLength(256, MinimumLength = 1)] string Audience,
    [Required, StringLength(256, MinimumLength = 1)] string DisplayName
);
