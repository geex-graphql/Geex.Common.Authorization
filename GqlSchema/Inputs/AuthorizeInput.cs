﻿using System.Collections.Generic;
using Geex.Common.Authorization.GqlSchema.Types;
using MongoDB.Bson;

namespace Geex.Common.Authorization.GqlSchema.Inputs
{
    public record AuthorizeInput
    {
        public AuthorizeTargetType AuthorizeTargetType { get; set; }
        public List<string> AllowedPermissions { get; set; }
        /// <summary>
        /// 授权目标:
        /// 用户: id, 角色: name
        /// </summary>
        public string Target { get; set; }
    }
}