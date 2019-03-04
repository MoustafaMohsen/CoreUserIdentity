using CoreUserIdentity.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CoreUserIdentity._UserIdentity
{
    /// <summary>
    /// Extension methods for working with Jwt bearer tokens
    /// </summary>
    public static class JwtToken
    {
        /// <summary>
        /// Generates a Jwt bearer token containing the users username
        /// </summary>
        /// <param name="user">The users details</param>
        /// <param name="appSettings">The appSettings to get Token Credentials</param>
        /// <param name="UserRoles">the user Roles</param>
        /// <param name="durationInDayes">Set the Expiration date from now in days</param>
        /// <returns></returns>
        public static string GenerateJwtToken<ApplicationUser>(ApplicationUser user,List<string> UserRoles , CoreUserAppSettings appSettings, int durationInDayes = 90)
            where ApplicationUser : MyIdentityUser
        {
            string userId = user.Id;
            string userName = user.UserName;

            string issuer = appSettings.jwt.Issuer;
            string audience = appSettings.jwt.Audience;
            string jwtkey = appSettings.jwt.SecretKey;

            return _generateToken(userId, userName, issuer, audience, jwtkey, UserRoles, durationInDayes);
        }

        /// <summary>
        /// Generates a Jwt bearer token containing the users username
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <param name="userName">the user name</param>
        /// <param name="UserRoles">the user Roles</param>
        /// <param name="appSettings">The appSettings to get Token Credentials</param>
        /// <param name="durationInDayes">Set the Expiration date from now in days</param>
        /// <returns></returns>
        public static string GenerateJwtToken(string userId, string userName, List<string> UserRoles, CoreUserAppSettings appSettings, int durationInDayes = 90)
        {
            string issuer = appSettings.jwt.Issuer;
            string audience = appSettings.jwt.Audience;
            string jwtkey = appSettings.jwt.SecretKey;

            return _generateToken(userId, userName, issuer, audience, jwtkey, UserRoles, durationInDayes);
        }


        private static string _generateToken( string userId ,string userName,string issuer ,string audience,string jwtkey, List<string> UserRoles,int durationInDayes)
        {
            var SigntureAlgorithm= SecurityAlgorithms.HmacSha256;

            // Set tokens claims
            List<Claim> claims = new List<Claim>
            {
                // Unique ID for this token
                new Claim( JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString("N") ),

                // User Id
                new Claim( ClaimTypes.NameIdentifier, userId ),

                // The username using the Identity name so it fills out the HttpContext.User.Identity.Name value
                new Claim( ClaimTypes.Name, userName ),
            };
            for (int i = 0; i < UserRoles.Count; i++)
            {
                var role = UserRoles[i];
                var roleClaim = new Claim("roles", $"{role}");
                claims.Add(roleClaim);
            }
            if (UserRoles.Count == 0)
            {
                claims.Add(new Claim("roles", ""));
            }

            // Create the credentials used to generate the token
            var credentials = new SigningCredentials(
                // Get the secret key from configuration
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtkey))
                // Signture crypto algorithm
                , SigntureAlgorithm);

            // Generate the Jwt Token
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                signingCredentials: credentials,
                // Expire if not used for 3 months
                expires: DateTime.Now.AddDays(durationInDayes)
                );

            // Return the generated token
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        //////////////////////
        public static string CustomGenerateToken(string key,string issuer,string audience,double hours, Claim[] claims)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var secToken = new JwtSecurityToken(
                signingCredentials: credentials,
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(hours)
                );

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(secToken);
        }

        public static ClaimsPrincipal CustomValidateToken(string token, string key, string issuer, string audience)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters(key, issuer, audience);

            SecurityToken validatedToken;
            var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
            return principal;
        }

        private static TokenValidationParameters GetValidationParameters(string key, string issuer, string audience)
        {
            return new TokenValidationParameters()
            {
                ValidateLifetime = true, // Because there is no expiration in the generated token
                ValidateAudience = true, // Because there is no audiance in the generated token
                ValidateIssuer = true,   // Because there is no issuer in the generated token
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)) // The same key as the one that generate the token
            };
        }

    }//class
}
