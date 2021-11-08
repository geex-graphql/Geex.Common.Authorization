using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Geex.Common.Abstraction;
using Geex.Common.Authorization.Casbin;
using Geex.Common.Identity.Api.Aggregates.Users.Events;

using MediatR;

namespace Geex.Common.Authorization.Handlers
{
    public class AuthorizationHandler : INotificationHandler<UserRoleChangedEvent>, IRequestHandler<GetSubjectPermissionsRequest, IEnumerable<string>>
    {
        public AuthorizationHandler(RbacEnforcer enforcer)
        {
            Enforcer = enforcer;
        }

        public RbacEnforcer Enforcer { get; init; }
        public async Task Handle(UserRoleChangedEvent notification, CancellationToken cancellationToken)
        {
            await Enforcer.SetRolesForUser(notification.UserId, notification.Roles);
        }

        /// <summary>Handles a request</summary>
        /// <param name="request">The request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Response from the request</returns>
        public async Task<IEnumerable<string>> Handle(GetSubjectPermissionsRequest request, CancellationToken cancellationToken)
        {
            return Enforcer.GetImplicitPermissionsForUser(request.Subject).Select(x => string.Join("_", x.Skip(1).ToArray()).Trim('_'));
        }
    }
}
