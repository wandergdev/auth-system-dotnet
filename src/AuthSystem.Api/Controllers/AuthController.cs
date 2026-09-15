using AuthSystem.Api.Data;
using AuthSystem.Api.Dtos;
using AuthSystem.Api.Models;
using AuthSystem.Api.Options;
using AuthSystem.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthSystem.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    UserManager<ApplicationUser> userManager,
    AppDbContext db,
    ITokenService tokenService,
    IMfaChallengeStore mfaChallengeStore,
    IClientApplicationService clientApplications,
    IOptions<JwtOptions> jwtOptions
) : ControllerBase
{
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;

    [HttpPost("register")]
    public async Task<ActionResult<TokenResponse>> Register(RegisterRequest request)
    {
        var app = await ResolveApplicationAsync(request.ClientId);
        if (app is null)
        {
            return BadRequest(new { message = $"La aplicación '{request.ClientId}' no existe o está inactiva." });
        }

        var existing = await userManager.FindByEmailAsync(request.Email);
        if (existing is not null)
        {
            return Conflict(new { message = "Ya existe una cuenta con ese email." });
        }

        var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
        var result = await userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
        }

        await userManager.AddToRoleAsync(user, ApplicationRole.QualifiedName(app.ClientId, "User"));

        var tokens = await IssueTokensAsync(user, app);
        return CreatedAtAction(nameof(Register), tokens);
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest request)
    {
        var app = await ResolveApplicationAsync(request.ClientId);
        if (app is null)
        {
            return BadRequest(new { message = $"La aplicación '{request.ClientId}' no existe o está inactiva." });
        }

        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
        {
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            var mfaToken = await mfaChallengeStore.CreateChallengeAsync(
                user.Id, app.Id, TimeSpan.FromMinutes(_jwtOptions.MfaChallengeMinutes));
            return Ok(new LoginResponse(true, mfaToken, null));
        }

        var tokens = await IssueTokensAsync(user, app);
        return Ok(new LoginResponse(false, null, tokens));
    }

    [HttpPost("login/2fa")]
    public async Task<ActionResult<TokenResponse>> LoginTwoFactor(TwoFactorLoginRequest request)
    {
        var challenge = await mfaChallengeStore.ConsumeChallengeAsync(request.MfaToken);
        if (challenge is null)
        {
            return Unauthorized(new { message = "El desafío de doble factor expiró o es inválido." });
        }

        var user = await userManager.FindByIdAsync(challenge.UserId.ToString());
        if (user is null)
        {
            return Unauthorized();
        }

        // The challenge carries the application the login started for, so the resulting
        // token is scoped to that same app and cannot be redirected to another one.
        var app = await db.ClientApplications.FirstOrDefaultAsync(a => a.Id == challenge.ClientApplicationId && a.IsActive);
        if (app is null)
        {
            return Unauthorized(new { message = "La aplicación del desafío ya no está disponible." });
        }

        var isValid = await userManager.VerifyTwoFactorTokenAsync(
            user, TokenOptions.DefaultAuthenticatorProvider, request.Code);
        if (!isValid)
        {
            return Unauthorized(new { message = "Código de verificación incorrecto." });
        }

        var tokens = await IssueTokensAsync(user, app);
        return Ok(tokens);
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh(RefreshRequest request)
    {
        var hash = tokenService.HashRefreshToken(request.RefreshToken);
        var stored = await db.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.TokenHash == hash);

        if (stored is null || !stored.IsActive)
        {
            return Unauthorized(new { message = "Refresh token inválido o expirado." });
        }

        var app = await db.ClientApplications.FirstOrDefaultAsync(a => a.Id == stored.ClientApplicationId && a.IsActive);
        if (app is null)
        {
            return Unauthorized(new { message = "La aplicación de este refresh token ya no está disponible." });
        }

        stored.RevokedAtUtc = DateTime.UtcNow;

        // Refreshing stays within the application the token was issued for: a refresh
        // token can never be exchanged for access to a different audience.
        var tokens = await IssueTokensAsync(stored.User, app);

        var newHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var newStored = await db.RefreshTokens.FirstAsync(rt => rt.TokenHash == newHash);
        stored.ReplacedByTokenId = newStored.Id;

        await db.SaveChangesAsync();

        return Ok(tokens);
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout(LogoutRequest request)
    {
        var hash = tokenService.HashRefreshToken(request.RefreshToken);
        var stored = await db.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == hash);
        if (stored is not null && stored.IsActive)
        {
            stored.RevokedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }

        return NoContent();
    }

    [HttpPost("2fa/setup")]
    [Authorize]
    public async Task<ActionResult<TwoFactorSetupResponse>> SetupTwoFactor()
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        await userManager.ResetAuthenticatorKeyAsync(user);
        var unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);

        var issuer = Uri.EscapeDataString(_jwtOptions.Issuer);
        var label = Uri.EscapeDataString(user.Email ?? user.Id.ToString());
        var authenticatorUri =
            $"otpauth://totp/{issuer}:{label}?secret={unformattedKey}&issuer={issuer}&digits=6";

        return Ok(new TwoFactorSetupResponse(unformattedKey!, authenticatorUri));
    }

    [HttpPost("2fa/enable")]
    [Authorize]
    public async Task<IActionResult> EnableTwoFactor(TwoFactorEnableRequest request)
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        var isValid = await userManager.VerifyTwoFactorTokenAsync(
            user, TokenOptions.DefaultAuthenticatorProvider, request.Code);
        if (!isValid)
        {
            return BadRequest(new { message = "Código de verificación incorrecto." });
        }

        await userManager.SetTwoFactorEnabledAsync(user, true);
        return NoContent();
    }

    [HttpPost("2fa/disable")]
    [Authorize]
    public async Task<IActionResult> DisableTwoFactor(TwoFactorDisableRequest request)
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        var isValid = await userManager.VerifyTwoFactorTokenAsync(
            user, TokenOptions.DefaultAuthenticatorProvider, request.Code);
        if (!isValid)
        {
            return BadRequest(new { message = "Código de verificación incorrecto." });
        }

        await userManager.SetTwoFactorEnabledAsync(user, false);
        return NoContent();
    }

    /// Resolves the requested client application, falling back to the default one when
    /// the caller does not name it.
    private async Task<ClientApplication?> ResolveApplicationAsync(string? clientId) =>
        await clientApplications.FindByClientIdAsync(
            string.IsNullOrWhiteSpace(clientId) ? DataSeeder.DefaultClientId : clientId);

    private async Task<TokenResponse> IssueTokensAsync(ApplicationUser user, ClientApplication app)
    {
        // Only the roles the user holds in this application travel in the token, stripped
        // of the "clientId:" qualifier they are stored under.
        var prefix = app.ClientId + ":";
        var roles = (await userManager.GetRolesAsync(user))
            .Where(r => r.StartsWith(prefix, StringComparison.Ordinal))
            .Select(r => r[prefix.Length..])
            .ToList();

        var (accessToken, expiresAtUtc) = tokenService.GenerateAccessToken(user, app, roles);
        var refreshToken = tokenService.GenerateRefreshToken();

        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            ClientApplicationId = app.Id,
            TokenHash = refreshToken.Hash,
            ExpiresAtUtc = refreshToken.ExpiresAtUtc,
        });
        await db.SaveChangesAsync();

        return new TokenResponse(accessToken, refreshToken.RawToken, expiresAtUtc);
    }
}
