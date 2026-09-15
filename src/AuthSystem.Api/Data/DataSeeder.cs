using AuthSystem.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Api.Data;

public static class DataSeeder
{
    /// Default client, kept deliberately as "AuthSystem.Clients": that is the audience
    /// consumers were built against before applications were modelled, so existing ones
    /// keep validating without a change.
    public const string DefaultClientId = "default";
    public const string DefaultAudience = "AuthSystem.Clients";

    private static readonly string[] DefaultRoles = ["Admin", "User"];

    public static async Task SeedAsync(IServiceProvider services, CancellationToken ct = default)
    {
        var db = services.GetRequiredService<AppDbContext>();
        var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();

        var defaultApp = await db.ClientApplications
            .FirstOrDefaultAsync(a => a.ClientId == DefaultClientId, ct);

        if (defaultApp is null)
        {
            defaultApp = new ClientApplication
            {
                ClientId = DefaultClientId,
                Audience = DefaultAudience,
                DisplayName = "Default client",
            };
            db.ClientApplications.Add(defaultApp);
            await db.SaveChangesAsync(ct);
        }

        await EnsureRolesAsync(roleManager, defaultApp, DefaultRoles);
    }

    /// Creates the standard role set for an application. Every app gets its own Admin
    /// and User, so "Admin" always means admin *of something*.
    public static async Task EnsureRolesAsync(
        RoleManager<ApplicationRole> roleManager, ClientApplication app, IEnumerable<string> roles)
    {
        foreach (var role in roles)
        {
            var qualified = ApplicationRole.QualifiedName(app.ClientId, role);
            if (!await roleManager.RoleExistsAsync(qualified))
            {
                await roleManager.CreateAsync(new ApplicationRole(app.Id, app.ClientId, role));
            }
        }
    }
}
