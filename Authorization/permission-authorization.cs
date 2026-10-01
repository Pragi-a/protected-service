using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace ProtectedService.Authorization;

public sealed record PermissionRequirement(string Permission) : IAuthorizationRequirement;

public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options)
    : DefaultAuthorizationPolicyProvider(options)
{
    private const string Prefix = "Permission:";

    public override Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (!policyName.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return base.GetPolicyAsync(policyName);
        }

        var permission = policyName[Prefix.Length..];
        var policy = new AuthorizationPolicyBuilder()
            .AddRequirements(new PermissionRequirement(permission))
            .Build();
        return Task.FromResult<AuthorizationPolicy?>(policy);
    }
}

public sealed class PermissionHandler : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        if (context.User.HasClaim("permission", requirement.Permission))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
