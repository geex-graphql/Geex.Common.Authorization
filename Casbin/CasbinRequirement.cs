using Microsoft.AspNetCore.Authorization;

namespace Geex.Common.Authorization.Casbin
{
    public class CasbinRequirement : IAuthorizationRequirement
    {
        public string Obj { get; }
        public string Act { get; }

        public CasbinRequirement(string obj, string act)
        {
            Obj = obj;
            Act = act;
        }

        public CasbinRequirement(string policyName)
        {
            this.Act = policyName;
            this.Obj = "*";
        }
    }
}