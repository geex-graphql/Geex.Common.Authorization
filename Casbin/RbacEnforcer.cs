using System.Collections.Generic;
using System.Linq;
using NetCasbin;
using NetCasbin.Model;

namespace Geex.Common.Authorization.Casbin
{
    public class RbacEnforcer : Enforcer
    {
        public RbacEnforcer(CasbinMongoAdapter adapter)
        {
            this.SetModel(Model);
            this.adapter = adapter;
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
            return base.AddNamedGroupingPolicy("g", sub, sub_group);
        }



        public bool SetUserGroupPolicy(string sub, IEnumerable<string> sub_groups)
        {
            var result = true;
            base.RemoveNamedGroupingPolicy("g", sub);
            foreach (var sub_group in sub_groups)
            {
                result = result && base.AddNamedGroupingPolicy("g", sub, sub_group);
            }
            return result;
        }


        public List<GroupPolicy> GetUserGroupPolicies(string sub)
        {
            return base.GetFilteredNamedGroupingPolicy("g", 0, sub).Select(x => new GroupPolicy(x)).ToList();
        }

        public bool AddResourceGroupPolicy(string resourceId, string groupId)
        {
            return base.AddNamedGroupingPolicy("g2", $"{resourceId}", $"{groupId}");
        }

        public bool SetFeaturePolicy(string sub, string[] objs)
        {
            var result = true;
            base.RemoveFilteredNamedPolicy("p", 0, sub);
            foreach (var obj in objs)
            {
                result = result && base.AddNamedPolicy("p", sub, obj, "*");
            }
            return result;
        }

        public bool SetResourcePolicy(string sub, string obj, string[] acts)
        {
            var result = true;
            base.RemoveNamedPolicy("p", sub, obj);
            foreach (var act in acts)
            {
                result = result && base.AddNamedPolicy("p", sub, obj, act);
            }

            return result;
        }

        public List<PolicyItem> GetFeaturePolicies(string sub)
        {
            var policies = base.GetFilteredNamedPolicy("p", 1, sub);
            return policies.Select(x => new PolicyItem(x)).ToList();
        }

        public List<PolicyItem> GetResourcePolicy(string sub, string obj)
        {
            var policies = base.GetFilteredNamedPolicy("p", 2, sub, obj);
            return policies.Select(x => new PolicyItem(x)).ToList();
        }

        public bool HasRoleForUser(string user, string role)
        {
            return base.HasRoleForUser(user, role);
        }

        public bool Enforce(string sub, string obj, string act = "*")
        {
            return base.Enforce(sub, obj, act);
        }

        public bool DeleteResourceGroupPolicy(string resourceOrGroupName)
        {
            return base.RemoveFilteredNamedGroupingPolicy("g2", 0, resourceOrGroupName);
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
                Group = @group;
            }

            public string Sub { get; }
            public string Group { get; }
        }


    }
}