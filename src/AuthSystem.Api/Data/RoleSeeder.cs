using Microsoft.AspNetCore.Identity;

namespace AuthSystem.Api.Data;

public static class RoleSeeder
{
    private static readonly string[] Roles = ["Admin", "User"];

    public static async Task SeedAsync(IServiceProvider services)
    {
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

        foreach (var role in Roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            }
        }
    }
}
