using System.IdentityModel.Tokens.Jwt;
using AuthSystem.Api.Services;
using Microsoft.AspNetCore.Authorization;

namespace AuthSystem.Api.Authorization;

/// Administration of the service itself: the client application registry.
///
/// Being Admin is not enough on its own. Roles are scoped to an application, so an Admin
/// of the CRM is an administrator *of the CRM* — granting them the registry would let
/// them mint audiences and deactivate other people's applications, which is exactly the
/// cross-application escalation that per-application audiences exist to prevent.
public class SystemAdminRequirement : IAuthorizationRequirement
{
    public const string PolicyName = "SystemAdmin";
}

public class SystemAdminHandler(IClientApplicationService registry)
    : AuthorizationHandler<SystemAdminRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, SystemAdminRequirement requirement)
    {
        if (!context.User.IsInRole("Admin"))
        {
            return Task.CompletedTask;
        }

        // The token must have been issued for the default application: that is what makes
        // its Admin role an administrator of the service rather than of some consumer.
        var systemAudience = registry.GetSystemAudience();
        if (systemAudience is null)
        {
            return Task.CompletedTask;
        }

        var audiences = context.User
            .FindAll(JwtRegisteredClaimNames.Aud)
            .Concat(context.User.FindAll("aud"))
            .Select(c => c.Value);

        if (audiences.Contains(systemAudience, StringComparer.Ordinal))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
