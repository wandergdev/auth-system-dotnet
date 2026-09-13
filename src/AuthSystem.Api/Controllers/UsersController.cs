using System.Security.Claims;
using AuthSystem.Api.Dtos;
using AuthSystem.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthSystem.Api.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<ApplicationUser> userManager) : ControllerBase
{
    [HttpGet("me")]
    public async Task<ActionResult<UserResponse>> Me()
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        var roles = await userManager.GetRolesAsync(user);
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
