using System.Collections.Generic;

using Microsoft.AspNetCore.Authorization;

namespace Geex.Common.Authorization.Casbin
{
    public class PolicyItem : IAuthorizationRequirement
    {
        public PolicyItem(List<string> x)
        {
            this.Sub = x[0];
            this.Obj = x[1];
            this.Act = x[2];
        }

        public PolicyItem(string sub, string obj, string act)
        {
            Sub = sub;
            Obj = obj;
            Act = act;
        }
        public string Sub { get; }
        public string Obj { get; }
        public string Act { get; }
    }
}