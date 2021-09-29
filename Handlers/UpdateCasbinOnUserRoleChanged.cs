using System.Threading;
using System.Threading.Tasks;
using Geex.Common.Authorization.Casbin;
using Geex.Common.Identity.Api.Aggregates.Users.Events;
using MediatR;

namespace Geex.Common.Authorization.Handlers
{
    public class UpdateCasbinOnUserRoleChanged : INotificationHandler<UserRoleChangedEvent>
    {
        public UpdateCasbinOnUserRoleChanged(RbacEnforcer enforcer)
        {
            Enforcer = enforcer;
        }

        public RbacEnforcer Enforcer { get; init; }
        public async Task Handle(UserRoleChangedEvent notification, CancellationToken cancellationToken)
        {
            Enforcer.SetRolesForUser(notification.UserId, notification.Roles);
        }
    }
}
