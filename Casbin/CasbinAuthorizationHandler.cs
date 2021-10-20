using System.Security.Claims;
using System.Threading.Tasks;

using HotChocolate.Resolvers;

using Microsoft.AspNetCore.Authorization;

using NetCasbin;

namespace Geex.Common.Authorization.Casbin
{
    public class CasbinAuthorizationHandler : AuthorizationHandler<CasbinRequirement, IResolverContext>
    {
        private readonly RbacEnforcer _enforcer;

        public CasbinAuthorizationHandler(RbacEnforcer enforcer)
        {
            _enforcer = enforcer;
        }

        /// <summary>
        /// Makes a decision if authorization is allowed based on a specific requirement and resource.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        /// <param name="resource">The resource to evaluate.</param>
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, CasbinRequirement requirement,
            IResolverContext resource)
        {
            var obj = requirement.Obj ?? "*"; // the resource that is going to be accessed.
            var act = requirement.Act ?? "*"; // the operation that the user performs on the resource.
            var fields = requirement.Fields ?? "*"; // the fields that the user is going to retrieve from the resource.
            if (await _enforcer.EnforceAsync(context.User.FindUserId(), obj, act, fields))
            {
                // permit alice to read data1
                context.Succeed(requirement);
            }
            else
            {
                // deny the request, show an error
                context.Fail();
            }

            return;
        }
    }
}
