using System.Collections.Generic;
using Geex.Common.Authorization.Abstraction;
using Geex.Common.Authorization.GqlSchema.Types;
using MongoDB.Bson;

namespace Geex.Common.Authorization.GqlSchema.Inputs
{
    public record AuthorizeInput
    {
        public AuthorizeTargetType AuthorizeTargetType { get; set; }
        public List<AppPermission> AllowedPermissions { get; set; }
        public ObjectId TargetId { get; set; }
    }
}