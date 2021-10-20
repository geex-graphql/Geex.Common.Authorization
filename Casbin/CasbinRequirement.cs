using System.Linq;

using Microsoft.AspNetCore.Authorization;

namespace Geex.Common.Authorization.Casbin
{
    public class CasbinRequirement : IAuthorizationRequirement
    {
        public string Obj { get; }
        public string Act { get; }
        public string Fields { get; set; }

        public CasbinRequirement(string policyName)
        {
            var split = policyName.Split('_');
            this.Obj = split[0];
            this.Act = split[1];
            this.Fields = split.ElementAtOrDefault(2) ?? "";
        }
    }
}