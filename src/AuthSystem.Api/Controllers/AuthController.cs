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
    IOptions<JwtOptions> jwtOptions
) : ControllerBase
{
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;

    [HttpPost("register")]
    public async Task<ActionResult<TokenResponse>> Register(RegisterRequest request)
    {
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

        await userManager.AddToRoleAsync(user, "User");

        var tokens = await IssueTokensAsync(user);
        return CreatedAtAction(nameof(Register), tokens);
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest request)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
        {
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            var mfaToken = mfaChallengeStore.CreateChallenge(user.Id, TimeSpan.FromMinutes(_jwtOptions.MfaChallengeMinutes));
            return Ok(new LoginResponse(true, mfaToken, null));
        }

        var tokens = await IssueTokensAsync(user);
        return Ok(new LoginResponse(false, null, tokens));
    }

    [HttpPost("login/2fa")]
    public async Task<ActionResult<TokenResponse>> LoginTwoFactor(TwoFactorLoginRequest request)
    {
        var userId = mfaChallengeStore.ConsumeChallenge(request.MfaToken);
        if (userId is null)
        {
            return Unauthorized(new { message = "El desafío de doble factor expiró o es inválido." });
        }

        var user = await userManager.FindByIdAsync(userId.Value.ToString());
        if (user is null)
        {
            return Unauthorized();
        }

        var isValid = await userManager.VerifyTwoFactorTokenAsync(
            user, TokenOptions.DefaultAuthenticatorProvider, request.Code);
        if (!isValid)
        {
            return Unauthorized(new { message = "Código de verificación incorrecto." });
        }

        var tokens = await IssueTokensAsync(user);
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

        stored.RevokedAtUtc = DateTime.UtcNow;

        var tokens = await IssueTokensAsync(stored.User);

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

    private async Task<TokenResponse> IssueTokensAsync(ApplicationUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        var (accessToken, expiresAtUtc) = tokenService.GenerateAccessToken(user, roles);
        var refreshToken = tokenService.GenerateRefreshToken();

        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshToken.Hash,
            ExpiresAtUtc = refreshToken.ExpiresAtUtc,
        });
        await db.SaveChangesAsync();

        return new TokenResponse(accessToken, refreshToken.RawToken, expiresAtUtc);
    }
}
