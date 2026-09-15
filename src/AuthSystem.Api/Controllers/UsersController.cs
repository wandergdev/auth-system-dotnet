using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthSystem.Api.Data;
using AuthSystem.Api.Dtos;
using AuthSystem.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Api.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<ApplicationUser> userManager, AppDbContext db) : ControllerBase
{
    [HttpGet("me")]
    public async Task<ActionResult<UserResponse>> Me()
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        // Report the roles the user holds in the application this token was issued for,
        // unqualified, so the answer matches what the token itself carries.
        var audience = User.FindFirstValue(JwtRegisteredClaimNames.Aud) ?? User.FindFirstValue("aud");
        var clientId = await db.ClientApplications
            .AsNoTracking()
            .Where(a => a.Audience == audience)
            .Select(a => a.ClientId)
            .FirstOrDefaultAsync();

        var allRoles = await userManager.GetRolesAsync(user);
        var roles = clientId is null
            ? allRoles
            : allRoles.Where(r => r.StartsWith(clientId + ":", StringComparison.Ordinal))
                      .Select(r => r[(clientId.Length + 1)..])
                      .ToList();

        return Ok(new UserResponse(user.Id, user.Email!, user.TwoFactorEnabled, roles));
    }

    /// Demo endpoint that shows role-based authorization in action.
    [HttpGet("admin-ping")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminPing()
    {
        var email = User.FindFirstValue(ClaimTypes.Email);
        return Ok(new { message = $"Hola {email}, tienes acceso de administrador." });
    }
}
