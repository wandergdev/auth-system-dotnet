using Microsoft.AspNetCore.Identity;

namespace AuthSystem.Api.Models;

public class ApplicationUser : IdentityUser<Guid>
{
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
