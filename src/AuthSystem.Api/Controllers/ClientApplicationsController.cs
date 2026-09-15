using AuthSystem.Api.Authorization;
using AuthSystem.Api.Data;
using AuthSystem.Api.Dtos;
using AuthSystem.Api.Models;
using AuthSystem.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Api.Controllers;

/// Registry of consuming applications.
///
/// Guarded by the SystemAdmin policy, not by the Admin role alone: roles belong to an
/// application, so an Admin of a consumer app must not be able to register audiences or
/// deactivate somebody else's application.
[ApiController]
[Route("api/applications")]
[Authorize(Policy = SystemAdminRequirement.PolicyName)]
public class ClientApplicationsController(
    AppDbContext db,
    RoleManager<ApplicationRole> roleManager,
    IClientApplicationService registry
) : ControllerBase
{
    private static readonly string[] DefaultRoles = ["Admin", "User"];

    [HttpGet]
    public async Task<ActionResult<IEnumerable<ClientApplicationResponse>>> List() =>
        Ok(await db.ClientApplications
            .AsNoTracking()
            .OrderBy(a => a.ClientId)
            .Select(a => new ClientApplicationResponse(a.ClientId, a.Audience, a.DisplayName, a.IsActive))
            .ToListAsync());

    [HttpPost]
    public async Task<ActionResult<ClientApplicationResponse>> Create(CreateClientApplicationRequest request)
    {
        var clientIdTaken = await db.ClientApplications.AnyAsync(a => a.ClientId == request.ClientId);
        if (clientIdTaken)
        {
            return Conflict(new { message = $"Ya existe una aplicación con el clientId '{request.ClientId}'." });
        }

        var audienceTaken = await db.ClientApplications.AnyAsync(a => a.Audience == request.Audience);
        if (audienceTaken)
        {
            // Two applications sharing an audience would defeat the isolation the
            // audience exists to provide.
            return Conflict(new { message = $"La audiencia '{request.Audience}' ya está en uso por otra aplicación." });
        }

        var app = new ClientApplication
        {
            ClientId = request.ClientId,
            Audience = request.Audience,
            DisplayName = request.DisplayName,
        };

        db.ClientApplications.Add(app);
        await db.SaveChangesAsync();

        await DataSeeder.EnsureRolesAsync(roleManager, app, DefaultRoles);

        // Make the new audience valid immediately on this instance; the others pick it
        // up when their snapshot expires.
        await registry.RefreshAsync();

        return CreatedAtAction(nameof(List),
            new ClientApplicationResponse(app.ClientId, app.Audience, app.DisplayName, app.IsActive));
    }

    /// Deactivating stops new tokens being issued and makes existing ones fail audience
    /// validation, without losing the application's roles or assignments.
    [HttpPost("{clientId}/deactivate")]
    public async Task<IActionResult> Deactivate(string clientId)
    {
        var app = await db.ClientApplications.FirstOrDefaultAsync(a => a.ClientId == clientId);
        if (app is null)
        {
            return NotFound();
        }

        if (app.ClientId == DataSeeder.DefaultClientId)
        {
            return BadRequest(new { message = "La aplicación por defecto no se puede desactivar." });
        }

        app.IsActive = false;
        await db.SaveChangesAsync();
        await registry.RefreshAsync();

        return NoContent();
    }
}
