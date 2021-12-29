﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

using MongoDB.Entities;

using NetCasbin;
using NetCasbin.Abstractions;

namespace Geex.Common.Authorization.Casbin
{
    public static class CasbinExtensions
    {
        public static void AddCasbinAuthorization(this IServiceCollection services)
        {
            // Replace the default authorization policy provider with our own
            // custom provider which can return authorization policies for given
            // policy names (instead of using the default policy provider)
            services.AddSingleton(x => new CasbinMongoAdapter(() => DB.Collection<CasbinRule>()));
            services.AddSingleton<RbacEnforcer>();
            services.AddSingleton<IEnforcer, RbacEnforcer>();
            services.AddAuthorization();
            services.AddSingleton<IAuthorizationPolicyProvider, CasbinAuthorizationPolicyProvider>();

            //// As always, handlers must be provided for the requirements of the authorization policies
            services.AddSingleton<IAuthorizationHandler, CasbinAuthorizationHandler>();
        }
    }
}