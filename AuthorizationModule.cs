using Geex.Common.Abstractions;
using Geex.Common.Authorization.Casbin;
using Microsoft.AspNetCore.Builder;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Modularity;

namespace Geex.Common.Authorization
{
    [DependsOn(
    )]
    public class AuthorizationModule : GeexModule<AuthorizationModule>
    {
        public override void ConfigureServices(ServiceConfigurationContext context)
        {
            var services = context.Services;
            services.AddCasbinAuthorization();
            base.ConfigureServices(context);
        }

        public override void OnApplicationInitialization(ApplicationInitializationContext context)
        {
            var app = context.GetApplicationBuilder();
            app.UseAuthorization();
            base.OnApplicationInitialization(context);
        }
    }
}
