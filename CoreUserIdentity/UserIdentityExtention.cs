using CoreUserIdentity.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using VerficationEmailSender;

namespace CoreUserIdentity._UserIdentity
{
    public static class UserIdentityExtention 
    {
        public static IServiceCollection AddMyUserIdentity<TContext, ApplicationUser>(
            this IServiceCollection services,
            Action<CoreUserAppSettings> setupAction
            ,string jwtkey, string audience, string issuer
            ) 
            where TContext : DbContext 
            where ApplicationUser : MyIdentityUser , new()
        {
            // Checking Parameters validity
            if (setupAction == null) throw new ArgumentNullException(nameof(setupAction));
            if (services == null) throw new ArgumentNullException(nameof(services));

            // Setup configuration
            services.Configure(setupAction);


            //============================================================
            // TODO: add if statment to see if email confirmation is enabled, remember to remove email sender injection
            //============================================================
            // Add my email service
            services.AddVerficationEmailSender();

            services.AddScoped< IUserIdentityManager<ApplicationUser>, UserIdentityManager<ApplicationUser> >();

            services.AddIdentity<ApplicationUser, IdentityRole>(
                a =>
                {
                    a.SignIn.RequireConfirmedEmail = true;
                    a.User.RequireUniqueEmail = true;
                    a.User.AllowedUserNameCharacters =
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+دجحخهعغفقثصضطكمنتالبيسشظزوةىرؤءئ";
                }
            ).AddEntityFrameworkStores<TContext>().AddDefaultTokenProviders();

            var key = Encoding.UTF8.GetBytes(jwtkey);
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(options => {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = issuer,
                        ValidAudience = audience,
                        IssuerSigningKey = new SymmetricSecurityKey(key)
                    };
                });

            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 6;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
            });

            services.AddScoped< IRunOnAppStart<ApplicationUser>, RunOnAppStart<ApplicationUser> >();

            // Return the Services
            return services;
        }
    }
}
