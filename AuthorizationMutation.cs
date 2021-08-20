using System.Threading.Tasks;
using Autofac;
using Geex.Common.Authorization.GqlSchema.Inputs;
using Geex.Common.Gql.Roots;
using HotChocolate;

namespace Geex.Common.Authorization
{
    public class AuthorizationMutation : MutationTypeExtension<AuthorizationMutation>
    {
        public async Task<bool> Authorize(
            [Service] IComponentContext componentContext,
            AuthorizeInput input)
        {
            var enforcer = componentContext.Resolve<RbacEnforcer>();
            await enforcer.SetPermissionsAsync(input.TargetId.ToString(), input.AllowedPermissions.ToArray());
            return true;
        }
    }
}
