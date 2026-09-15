using Microsoft.AspNetCore.Identity;

namespace AuthSystem.Api.Models;

/// A role scoped to one client application: you can be Admin in the CRM and User in
/// finance. Identity keeps a unique index on the normalized role name, so the stored
/// Name is qualified ("crm-app:Admin") while RoleName holds the bare name that goes
/// into the token.
public class ApplicationRole : IdentityRole<Guid>
{
    public Guid? ClientApplicationId { get; set; }

    /// Unqualified role name, as emitted in the token ("Admin").
    public string RoleName { get; set; } = null!;

    public ApplicationRole() { }

    public ApplicationRole(Guid clientApplicationId, string clientId, string roleName)
        : base(QualifiedName(clientId, roleName))
    {
        ClientApplicationId = clientApplicationId;
        RoleName = roleName;
    }

    /// Identity's role names are globally unique, so "Admin" in two applications would
    /// collide. Qualifying by clientId keeps them distinct in storage while the token
    /// still carries the plain name the consumer expects.
    public static string QualifiedName(string clientId, string roleName) => $"{clientId}:{roleName}";
}
