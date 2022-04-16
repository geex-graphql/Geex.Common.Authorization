using System.Linq;
using System.Threading.Tasks;
using Autofac;
using Geex.Common.Abstraction.Gql.Types;
using Geex.Common.Authorization.Casbin;
using Geex.Common.Authorization.GqlSchema.Inputs;
using HotChocolate;

namespace Geex.Common.Authorization
{
    public class AuthorizationMutation : Mutation<AuthorizationMutation>
    {
        public async Task<bool> Authorize(
            [Service] RbacEnforcer enforcer,
            AuthorizeInput input)
        {
            await enforcer.SetPermissionsAsync(input.Target.ToString(), input.AllowedPermissions.Select(x=>x.Value).ToArray());
            return true;
        }
    }
}
