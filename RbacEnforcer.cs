using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Geex.Common.Abstraction;
using Geex.Common.Abstractions;
using Geex.Common.Authorization.Abstraction;
using Geex.Common.Authorization.Casbin;
using Geex.Common.Authorization.Events;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using NetCasbin;
using NetCasbin.Model;

namespace Geex.Common.Authorization
{
    public class RbacEnforcer : Enforcer
    {
        public RbacEnforcer(CasbinMongoAdapter adapter) : base(Model, adapter)
        {
        }
        /// <summary>
        /// # defines
        /// p, user.1, data.1, read
        /// p, user.2, data.2, write
        /// p, user_group.1, data_group.1, write
        /// 
        /// g, user.1, user_group.1
        /// g2, data.1, data_group.1
        /// g2, data.2, data_group.1
        ///
        /// # requests
        /// user.1, data.1, read : true
        /// user.1, data.1, write : true
        /// user.1, data.2, read : false
        /// user.1, data.2, write : true
        /// </summary>
        public static Model Model { get; } = Model.CreateDefaultFromText(@"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (p.sub == ""*"" || g(r.sub, p.sub)) && (p.obj == ""*"" || g2(r.obj, p.obj)) && (p.act == ""*"" || r.act == p.act)
");



        public bool AddUserGroupPolicy(string sub, string sub_group)
        {
            return this.AddNamedGroupingPolicy("g", sub, sub_group);
        }



        public bool SetUserGroupPolicy(string sub, IEnumerable<string> sub_groups)
        {
            var result = true;
            this.RemoveNamedGroupingPolicy("g", sub);
            foreach (var sub_group in sub_groups)
            {
                result = result && this.AddNamedGroupingPolicy("g", sub, sub_group);
            }
            return result;
        }


        public List<GroupPolicy> GetUserGroupPolicies(string sub)
        {
            return this.GetFilteredNamedGroupingPolicy("g", 0, sub).Select(x => new GroupPolicy(x)).ToList();
        }

        public bool AddResourceGroupPolicy(string resourceId, string groupId)
        {
            return this.AddNamedGroupingPolicy("g2", $"{resourceId}", $"{groupId}");
        }

        public bool SetFeaturePolicy(string sub, string[] objs)
        {
            var result = true;
            this.RemoveFilteredNamedPolicy("p", 0, sub);
            foreach (var obj in objs)
            {
                result = result && this.AddNamedPolicy("p", sub, obj, "*");
            }
            return result;
        }

        public bool SetResourcePolicy(string sub, string obj, string[] acts)
        {
            var result = true;
            this.RemoveNamedPolicy("p", sub, obj);
            foreach (var act in acts)
            {
                result = result && this.AddNamedPolicy("p", sub, obj, act);
            }

            return result;
        }

        public List<PolicyItem> GetFeaturePolicies(string sub)
        {
            var policies = this.GetFilteredNamedPolicy("p", 1, sub);
            return policies.Select(x => new PolicyItem(x)).ToList();
        }

        public List<PolicyItem> GetResourcePolicy(string sub, string obj)
        {
            var policies = this.GetFilteredNamedPolicy("p", 2, sub, obj);
            return policies.Select(x => new PolicyItem(x)).ToList();
        }

        public bool Enforce(string sub, string obj, string act = "*")
        {
            return base.Enforce(sub, obj, act);
        }

        public bool DeleteResourceGroupPolicy(string resourceOrGroupName)
        {
            return this.RemoveFilteredNamedGroupingPolicy("g2", 0, resourceOrGroupName);
        }

        public class GroupPolicy
        {
            public GroupPolicy(List<string> x)
            {
                this.Sub = x[0];
                this.Group = x[1];
            }

            public GroupPolicy(string sub, string group)
            {
                Sub = sub;
                Group = group;
            }

            public string Sub { get; }
            public string Group { get; }
        }

        public void SetRolesForUser(string userId, List<string> roles)
        {
            var originRole = this.GetRolesForUser(userId);
            var newRoles = roles.Intersect(originRole);
            var removedRoles = originRole.Except(roles);
            foreach (string newRole in newRoles)
            {
                this.AddRoleForUser(userId, newRole);
            }
            foreach (string removedRole in removedRoles)
            {
                this.DeleteRoleForUser(userId, removedRole);
            }

        }

        public async Task SetPermissionsAsync(string subId, params AppPermission[] permissions)
        {
            await this.DeletePermissionsForUserAsync(subId);
            await this.AddPermissionForUserAsync(subId,
                permissions.Cast<AppPermission, string>().ToList());
            await ServiceLocator.Current.GetService<IMediator>().Publish(new PermissionChangedEvent(subId, permissions));
        }
    }
}
