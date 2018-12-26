using CoreUserIdentity.Helpers;
using CoreUserIdentity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MLiberary;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using VerficationEmailSender;
using VerficationEmailSender.Models;
using VerficationEmailSender.SendGrid;

namespace CoreUserIdentity._UserIdentity
{
    public interface IUserIdentityManager<ApplicationUser, TDbContext>
    {
        #region Interfaces

        /// <summary>
        /// Tries to register for a new account on the server
        /// </summary>
        /// <param name="registerCredentials">The registration details</param>
        /// <param name="host">The Domain Host, Required to generate the user Verfication Url</param>
        /// <returns>Returns the result of the register request</returns>
        Task<ApplicationUser> RegisterAsync(_IdentityUserDto registerCredentials, string host, string urlpath, bool sendEmail = true, string role = "", bool confirmEmail = false);

        /// <summary>
        /// Register user user user template, default role is client
        /// </summary>
        /// <param name="Newuser"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        Task<ApplicationUser> StrongRegisterAsync(ApplicationUser Newuser, string role = "");

        /// <summary>
        /// Logs in a user using token-based authentication
        /// </summary>
        /// <returns>Returns the result of the login request</returns>
        Task<_IdentityUserDto> LogInAsync(LoginUserDto loginCredentials);

        /// <summary>
        /// Login without password
        /// </summary>
        /// <param name="usernameOrEmail">username or password</param>
        /// <returns></returns>
        Task<_IdentityUserDto> LogInWithoutPassword(string usernameOrEmail);

        /// <summary>
        /// Verfiy User's Email
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <param name="emailToken">the user email verfication code</param>
        /// <returns></returns>
        Task<IdentityResult> VerifyEmailAsync(string userId, string emailToken);

        /// <summary>
        /// Send email verfication code to user email
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <param name="host">the host domain</param>
        /// <param name="force">Send email verfication even if email already confirmed</param>
        /// <returns></returns>
        Task<SendEmailResponse> sendEmailVerfication(string userId, string host, string urlpath, bool force = false);

        /// <summary>
        /// Get user object by id
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <returns></returns>
        Task<ApplicationUser> GetUserById(string userId);

        /// <summary>
        /// Get user object by id, include the role and token, returns _IdentityUserDto
        /// </summary>
        /// <param name="userId">the user id</</param>
        /// <returns></returns>
        Task<_IdentityUserDto> GetUserById_includeRoleAsync(string userId);

        /// <summary>
        /// Get user, Include External logins
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <returns></returns>
        Task<ApplicationUser> GetUser_IncludeExternalLogins(string userId);

        /// <summary>
        /// Get NameIdentifier Claim from list of claims 
        /// </summary>
        /// <param name="claims">The list of claims</param>
        /// <returns></returns>
        Claim FindClaimNameIdentifier(IEnumerable<Claim> claims);

        /// <summary>
        /// Find claim from list of claims
        /// </summary>
        /// <param name="claims">The list of claims</param>
        /// <param name="ClaimType">The claim type, use Claimtypes class to get claim type</param>
        /// <returns></returns>
        Claim FindClaim(IEnumerable<Claim> claims, string ClaimType);

        /// <summary>
        /// Get User roles
        /// </summary>
        /// <param name="user">The identity User</param>
        /// <returns></returns>
        Task<List<string>> GetUserRoles(ApplicationUser user);

        /// <summary>
        /// Get User Biggest Role
        /// </summary>
        /// <param name="user">The identity User</param>
        /// <returns></returns>
        Task<string> GetUserRole(ApplicationUser user);

        /// <summary>
        /// Is User has Role
        /// </summary>
        /// <param name="user">The identity User</param>
        /// <param name="role">the role</param>
        /// <returns></returns>
        Task<bool> UserHasRole(ApplicationUser user, string role);

        /// <summary>
        /// Get biggest roles from list of roles
        /// </summary>
        /// <param name="roles">the list of roles</param>
        /// <returns></returns>
        string GetBiggestRole(IList<string> roles);
        /// <summary>
        /// Add role to user if it deosn't already have the role, and return result, return true if role added or user already has the role
        /// </summary>
        /// <param name="user">The identity User</param>
        /// <param name="roleName">The role name</param>
        /// <param name="AutoCreate">If the role does't exsist, Create it?(default:false)</param>
        /// <returns></returns>
        Task<bool> AddRoleToUser(ApplicationUser user, string roleName, bool AutoCreate = false);

        /// <summary>
        /// Remove role from user if it already has the role, and return the results, return true if user doesn't have the role
        /// </summary>
        /// <param name="user">The identity User</param>
        /// <param name="roleName">The role name</param>
        /// <returns></returns>
        Task<bool> RemoveRoleFromUser(ApplicationUser user, string roleName);

        /// <summary>
        /// Removes all the user Role
        /// </summary>
        /// <param name="user">The identity User</param>
        /// <returns></returns>
        Task<bool> RemoveAllRolesFromUser(ApplicationUser user);

        /// <summary>
        /// Create A new Role, return the results and retun true if already exsists
        /// </summary>
        /// <param name="name">The role name</param>
        /// <returns></returns>
        Task<bool> CreateRole(string name);

        /// <summary>
        /// Check password is correct
        /// </summary>
        /// <param name="UserId">the user id</param>
        /// <param name="Password">the check password</param>
        /// <returns></returns>
        Task<bool> CheckPasswordAsync(string UserId, string Password);

        /// <summary>
        /// Check password is correct
        /// </summary>
        /// <param name="user">the identity user</param>
        /// <param name="Password">the check password</param>
        /// <returns></returns>
        Task<bool> CheckPasswordAsync(ApplicationUser user, string Password);

        /// <summary>
        /// Is email unique, never taken before
        /// </summary>
        /// <param name="Email">the checked email</param>
        /// <returns></returns>
        Task<bool> IsEmailUnique(string Email);

        /// <summary>
        /// Get User by Email
        /// </summary>
        /// <param name="email">user email</param>
        /// <returns></returns>
        Task<ApplicationUser> GetUserByEmail(string email);

        /// <summary>
        /// Get user by username
        /// </summary>
        /// <param name="username">username</param>
        /// <returns></returns>
        Task<ApplicationUser> GetUserByUsername(string username);


        /// <summary>
        /// Is username unique, never taken before
        /// </summary>
        /// <param name="Email">the checked username</param>
        /// <returns></returns>
        Task<bool> IsUserameUnique(string Username);

        /// <summary>
        /// Converts Application user to UserDto object, adds role
        /// </summary>
        /// <param name="userIdentity">the user object</param>
        /// <param name="userRole">one role</param>
        /// <returns></returns>
        Task<_IdentityUserDto> ApplicationUser_ToUserDto(ApplicationUser userIdentity, string userRole);

        /// <summary>
        /// Converts Application user to UserDto object, adds roles
        /// </summary>
        /// <param name="userIdentity">the user object</param>
        /// <param name="userRole">roles</param>
        /// <returns></returns>
        Task<_IdentityUserDto> ApplicationUser_ToUserDto(ApplicationUser userIdentity, List<string> userRoles);

        /// <summary>
        /// update User information... firstname, lastname, email... password is requird to successfull update 
        /// </summary>
        /// <param name="editUserDto">the edit user dto</param>
        /// <returns></returns>
        Task<ApplicationUser> UpdateInfoAsync(_IdentityUserDto editUserDto, bool requirePassword = true);

        /// <summary>
        /// Update Entity Info
        /// </summary>
        /// <param name="editUserDto">the updated user</param>
        /// <returns></returns>
        Task<ApplicationUser> StrongUpdateAsync(ApplicationUser editUserDto);

        /// <summary>
        /// Update user password
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <param name="oldPassword">the old password</param>
        /// <param name="newPassword">the new password</param>
        /// <returns></returns>
        Task<ApplicationUser> UpdatePasswordAsync(string userId, string oldPassword, string newPassword);

        /// <summary>
        /// Premnently Delete user
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <param name="Password">the user password</param>
        /// <returns></returns>
        Task<bool> DeleteUserAsync(string userId, string Password);

        /// <summary>
        /// Generate token using user id
        /// </summary>
        /// <param name="userId">the user id</param>
        /// <param name="ExperationInDayes">the Token experation days</param>
        /// <returns></returns>
        Task<string> GenerateTokenAsync(string userId, int ExperationInDayes = 90);

        /// <summary>
        /// Generate token using user
        /// </summary>
        /// <param name="user">the user identity</param>
        /// <param name="ExperationInDayes">the Token experation days</param>
        /// <returns></returns>
        Task<string> GenerateTokenAsync(ApplicationUser user, int ExperationInDayes = 90);

        /// <summary>
        /// Get all users, using user manager
        /// </summary>
        /// <returns></returns>
        IQueryable<ApplicationUser> GetAllUsersAsync();
        #endregion
    }
    public class UserIdentityManager<ApplicationUser, TDbContext> : IUserIdentityManager<ApplicationUser, TDbContext>
        where ApplicationUser : MyIdentityUser, new()
        where TDbContext : IdentityDbContext<ApplicationUser>
    {
        #region Class
        #region Protected Members
        protected CoreUserAppSettings userAppSettings;
        protected UserManager<ApplicationUser> mUserManager;
        protected SignInManager<ApplicationUser> mSignInManager;
        protected IVerificationEmail verificationEmail;
        protected RoleManager<IdentityRole> roleManager;
        protected TDbContext db;
        #endregion
        #region Constructor
        public UserIdentityManager(
            IOptions<CoreUserAppSettings> _options,
            UserManager<ApplicationUser> _mUserManager,
            SignInManager<ApplicationUser> _mSignInManager
            , IVerificationEmail _verification,
            RoleManager<IdentityRole> _roleManager,
            TDbContext _db
            )
        {
            mUserManager = _mUserManager;
            mSignInManager = _mSignInManager;
            userAppSettings = _options.Value;
            verificationEmail = _verification;
            roleManager = _roleManager;
            db = _db;
        }
        #endregion


        #region User Login and Registration and authentication Methods
        public async Task<ApplicationUser> RegisterAsync
            (_IdentityUserDto registerCredentials, string host, string urlpath, bool sendEmail = true, string role = "", bool confirmEmail = false)
        {
            // Make sure we have a user name
            if (registerCredentials == null ||
                string.IsNullOrWhiteSpace(registerCredentials.UserName) ||
                string.IsNullOrWhiteSpace(registerCredentials.password) ||
                string.IsNullOrWhiteSpace(registerCredentials.FirstName) ||
                string.IsNullOrWhiteSpace(registerCredentials.LastName)
                )
                // Return error message to user
                throw new CoreUserAppException("Empty Registration Info");

            // Create the desired user from the given details
            var Newuser = new ApplicationUser()
            {
                UserName = registerCredentials.UserName,
                FirstName = registerCredentials.FirstName,
                LastName = registerCredentials.LastName,
                Email = registerCredentials.Email
            };

            // Try and create a user
            IdentityResult result;
            try
            {
                result = await mUserManager.CreateAsync(Newuser, registerCredentials.password);
            }
            catch (Exception ex)
            {
                if (Debugger.IsAttached)
                    Debugger.Break();
                throw ex;
            }


            // If the registration was successful...
            if (result.Succeeded)
            {
                // Get the user details
                var userIdentity = await mUserManager.FindByNameAsync(registerCredentials.UserName);
                //if role parameter is not set then add role unverfied if Email is not confirmed
                string userRole = role;
                if (string.IsNullOrEmpty(role))
                {
                    userRole = userIdentity.EmailConfirmed ? MyRoles.client : MyRoles.unverfied;
                }
                // if email confirmation is disabled
                if (userAppSettings.serviceIdentitySettings.UseEmailConfirmation == false)
                {
                    confirmEmail = true;
                }
                if (confirmEmail)
                {
                    var emailVerificationCode = await mUserManager.GenerateEmailConfirmationTokenAsync(userIdentity);
                    await mUserManager.ConfirmEmailAsync(userIdentity, emailVerificationCode);
                }
                else
                {
                    if (userIdentity.EmailConfirmed == false && sendEmail)
                    {
                        try
                        {
                            await mUserManager.AddToRoleAsync(userIdentity, userRole);
                        }
                        catch (Exception ex)
                        {
                            if (Debugger.IsAttached)
                                Debugger.Break();
                            throw ex;
                        }
                        //set unverfied role
                        // Send verfication email
                        try
                        {
                            await sendVerfication(userIdentity, host, urlpath);
                        }
                        catch (Exception ex)
                        {
                            if (Debugger.IsAttached)
                                Debugger.Break();
                            throw ex;
                        }
                    }
                }


                // Return valid response containing all users details
                return userIdentity;
            }
            // Otherwise if it failed...
            else
                // Return the failed response
                // Aggregate all errors into a single error string
                throw new CoreUserAppException(result.Errors?.ToList()
                        .Select(f => f.Description)
                        .Aggregate((a, b) => $"{a}{Environment.NewLine}{b}"));
        }

        public async Task<ApplicationUser> StrongRegisterAsync(ApplicationUser Newuser, string role = "")
        {
            // Try and create a user
            IdentityResult result;
            try
            {
                result = await mUserManager.CreateAsync(Newuser);
            }
            catch (Exception ex)
            {
                if (Debugger.IsAttached)
                    Debugger.Break();
                throw ex;
            }


            // If the registration was successful add role
            if (result.Succeeded)
            {
                var userIdentity = await mUserManager.FindByNameAsync(Newuser.UserName);
                string userRole = role;
                if (string.IsNullOrEmpty(role))
                {
                    userRole = MyRoles.client;
                }
                try
                {
                    await mUserManager.AddToRoleAsync(userIdentity, userRole);
                }
                catch (Exception ex)
                {

                    throw ex;
                }



                // Return valid response containing all users details
                return userIdentity;
            }
            // Otherwise if it failed...
            else
            // Return the failed response
            // Aggregate all errors into a single error string
            if (Debugger.IsAttached)
                Debugger.Break();

            throw new CoreUserAppException(result.Errors?.ToList()
                        .Select(f => f.Description)
                        .Aggregate((a, b) => $"{a}{Environment.NewLine}{b}"));
        }

        public async Task<_IdentityUserDto> LogInAsync(LoginUserDto loginCredentials)
        {
            // Make sure we have a user name
            if (loginCredentials?.usernameOrEmail == null || string.IsNullOrWhiteSpace(loginCredentials.usernameOrEmail))
                // Return error message to user
                throw new CoreUserAppException("Invalid username or password");


            // Is it an email?
            var isEmail = GeneralMethods.IsEmail(loginCredentials.usernameOrEmail);

            // Get the user details
            var user = isEmail ?
                // Find by email
                await mUserManager.FindByEmailAsync(loginCredentials.usernameOrEmail) :
                // Find by username
                await mUserManager.FindByNameAsync(loginCredentials.usernameOrEmail);

            // If we failed to find a user...
            if (user == null)
                // Return error message to user
                throw new CoreUserAppException("Invalid username or password");

            // If we got here we have a user...
            // Let's validate the password

            // Get if password is valid
            var isValidPassword = await mUserManager.CheckPasswordAsync(user, loginCredentials.password);

            // If the password was wrong
            if (!isValidPassword)
                // Return error message to user
                throw new CoreUserAppException("Invalid username or password");

            // If we get here, we are valid and the user passed the correct login details

            // Get username
            var username = user.UserName;
            var role = await GetUserRoles(user);
            // Return token to user
            return new _IdentityUserDto
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                role = GetBiggestRole(role),
                UserName = user.UserName,
                token = JwtToken.GenerateJwtToken(user, role.ToList(), userAppSettings)
            };
        }

        public async Task<_IdentityUserDto> LogInWithoutPassword(string usernameOrEmail)
        {
            // Make sure we have a user name
            if (string.IsNullOrWhiteSpace(usernameOrEmail))
                // Return error message to user
                throw new CoreUserAppException("Invalid Input");


            // Is it an email?
            var isEmail = GeneralMethods.IsEmail(usernameOrEmail);

            // Get the user details
            var user = isEmail ?
                // Find by email
                await mUserManager.FindByEmailAsync(usernameOrEmail) :
                // Find by username
                await mUserManager.FindByNameAsync(usernameOrEmail);

            // If we failed to find a user...
            if (user == null)
                // Return error message to user
                throw new CoreUserAppException("User Not Found");

            // Get username
            var role = await GetUserRoles(user);
            // Return token to user
            return new _IdentityUserDto
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                role = GetBiggestRole(role),
                UserName = user.UserName,
                token = JwtToken.GenerateJwtToken(user, role.ToList(), userAppSettings)
            };
        }

        public async Task<string> GenerateTokenAsync(string userId, int ExperationInDayes = 90)
        {
            try
            {
                var user = await GetUserById(userId);
                if (user != null)
                {
                    var roles = await GetUserRoles(user);
                    return JwtToken.GenerateJwtToken(user, roles, userAppSettings, ExperationInDayes);
                }
                throw new CoreUserAppException("User not found");
            }
            catch (Exception ex)
            {
                throw new CoreUserAppException("Operation not succeful");
            }
        }
        public async Task<string> GenerateTokenAsync(ApplicationUser user, int ExperationInDayes = 90)
        {
            try
            {
                if (user != null)
                {
                    var roles = await GetUserRoles(user);
                    return JwtToken.GenerateJwtToken(user, roles, userAppSettings, ExperationInDayes);
                }
                throw new CoreUserAppException("User not found");
            }
            catch (Exception ex)
            {
                throw new CoreUserAppException("Operation not succeful");
            }
        }

        #endregion

        #region User Helpers
        public async Task<ApplicationUser> GetUser_IncludeExternalLogins(string userId)
        {
            var user = await db.Users
                .Where(x => x.Id == userId)
                .Include(x => x.ExternalLogin)
                .ThenInclude(x => x.OtherUserInfo)
                .FirstOrDefaultAsync();

            return user;
        }
        public async Task<bool> CheckPasswordAsync(string UserId, string Password)
        {
            var user = await GetUserById(UserId);
            if (user != null)
                return await mUserManager.CheckPasswordAsync(user, Password);
            return false;
        }
        public async Task<bool> CheckPasswordAsync(ApplicationUser user, string Password)
        {
            if (user != null)
                return await mUserManager.CheckPasswordAsync(user, Password);
            return false;
        }
        public async Task<bool> IsEmailUnique(string Email)
        {
            {
                Email = Email.ToUpper();
                try
                {
                    var user = await mUserManager.FindByEmailAsync(Email);
                    if (user != null)
                    {
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    throw new CoreUserAppException(ex.Message);
                }
                return false;
            }
        }
        public async Task<bool> IsUserameUnique(string Username)
        {
            {
                Username = Username.ToUpper();
                try
                {
                    var user = await mUserManager.FindByNameAsync(Username);
                    if (user != null)
                    {
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    throw new CoreUserAppException(ex.Message);
                }
                return false;
            }
        }
        public async Task<_IdentityUserDto> ApplicationUser_ToUserDto(ApplicationUser userIdentity, string userRole)
        {
            return new _IdentityUserDto
            {
                Id = userIdentity.Id,
                FirstName = userIdentity.FirstName,
                LastName = userIdentity.LastName,
                Email = userIdentity.Email,
                UserName = userIdentity.UserName,
                token = JwtToken.GenerateJwtToken(userIdentity, new List<string>() { userRole }, userAppSettings),
                role = userRole
            };
        }
        public async Task<_IdentityUserDto> ApplicationUser_ToUserDto(ApplicationUser userIdentity, List<string> userRoles)
        {
            var role = GetBiggestRole(userRoles);
            return new _IdentityUserDto
            {
                Id = userIdentity.Id,
                FirstName = userIdentity.FirstName,
                LastName = userIdentity.LastName,
                Email = userIdentity.Email,
                UserName = userIdentity.UserName,
                token = JwtToken.GenerateJwtToken(userIdentity, userRoles, userAppSettings),
                role = role
            };
        }
        #endregion

        #region User Update
        // thrower
        public async Task<ApplicationUser> UpdateInfoAsync(_IdentityUserDto editUserDto, bool requirePassword = true)
        {
            var IdeneityUser = await GetUserById(editUserDto.Id);

            // Make sure we have a user name
            if (IdeneityUser == null)
                // Return error message to user
                throw new CoreUserAppException("User not found");
            //Check password
            if (requirePassword)
            {
                var PasswordCorrect = await mUserManager.CheckPasswordAsync(IdeneityUser, editUserDto.password);

                if (PasswordCorrect == false)
                    throw new CoreUserAppException("Password is Incorrect");
            }


            // UpdateUsername
            IdeneityUser.FirstName = UpdateInput(IdeneityUser.FirstName, editUserDto.FirstName);
            IdeneityUser.LastName = UpdateInput(IdeneityUser.LastName, editUserDto.LastName);
            if (ValueChanged(IdeneityUser.Email, editUserDto.Email))
                if (await IsEmailUnique(editUserDto.Email))
                    IdeneityUser.Email = UpdateInput(IdeneityUser.Email, editUserDto.Email);

            try
            {
                var result = await mUserManager.UpdateAsync(IdeneityUser);
                if (result.Succeeded)
                {
                    var returnIdentityUser = await GetUserById(IdeneityUser.Id);
                    return returnIdentityUser;
                }
                throw new CoreUserAppException("Operation not Succesfull");
            }
            catch (Exception ex)
            {
                throw new CoreUserAppException(ex.Message);
            }


        }
        public async Task<ApplicationUser> StrongUpdateAsync(ApplicationUser editUserDto)
        {
            var IdeneityUser = await GetUserById(editUserDto.Id);

            // Make sure we have a user name
            if (IdeneityUser == null)
                // Return error message to user
                throw new CoreUserAppException("User not found");

            try
            {
                var result = await mUserManager.UpdateAsync(IdeneityUser);
                if (result.Succeeded)
                {
                    var returnIdentityUser = await GetUserById(IdeneityUser.Id);
                    return returnIdentityUser;
                }
                throw new CoreUserAppException("Operation not Succesfull");
            }
            catch (Exception ex)
            {
                throw new CoreUserAppException(ex.Message);
            }
        }
        // thrower
        public async Task<ApplicationUser> UpdatePasswordAsync(string userId, string oldPassword, string newPassword)
        {
            if (ValueChanged(oldPassword, newPassword))
            {
                var user = await GetUserById(userId);
                if (user != null)
                {
                    var PasswordCorrect = await CheckPasswordAsync(user.Id, oldPassword);
                    if (PasswordCorrect)
                    {
                        var result = await mUserManager.ChangePasswordAsync(user, oldPassword, newPassword);
                        if (result.Succeeded)
                        {
                            return await GetUserById(user.Id);
                        }
                        throw new CoreUserAppException("Operation failed");
                    }
                    else
                    {
                        throw new CoreUserAppException("Password is Incorrect");
                    }
                }
                else
                {
                    throw new CoreUserAppException("User not Found");
                }
            }
            else
                throw new CoreUserAppException("oldPassoword and new password are the same");
        }
        // thrower
        public async Task<bool> DeleteUserAsync(string userId, string Password)
        {
            var user = await GetUserById(userId);
            if (user != null)
            {
                //check password
                var PasswordCorrect = await CheckPasswordAsync(user, Password);
                if (PasswordCorrect)
                {
                    var results = await mUserManager.DeleteAsync(user);
                    return results.Succeeded;
                }
                else
                {
                    throw new CoreUserAppException("Password Is Incorrect");
                }
            }
            throw new CoreUserAppException("User not found");
        }
        #endregion

        #region Admin Methods
        public IQueryable<ApplicationUser> GetAllUsersAsync()
        {
            var users = mUserManager.Users;
            return users;
        }
        #endregion

        #region General Internal Methods
        public bool ValueChanged(string OldValue, string NewValue)
        {
            if (OldValue.ToUpper() != NewValue.ToUpper())
            {
                return true;
            }
            return false;
        }
        public string UpdateInput(string OldValue, string NewValue)
        {
            if (String.IsNullOrWhiteSpace(NewValue))
            {
                return OldValue;
            }
            if (ValueChanged(OldValue, NewValue))
            {
                return NewValue;
            }
            return OldValue;
        }
        #endregion

        #region User Role Managing
        public async Task<bool> CreateRole(string name)
        {
            var role = new IdentityRole();
            role.Name = name;
            try
            {
                var exsists = await RoleExsists(name);
                if (exsists == false)
                {
                    var resutl = await roleManager.CreateAsync(role);
                    return resutl.Succeeded;
                }
                else
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (Debugger.IsAttached)
                    Debugger.Break();
                throw ex;
            }
        }
        public string GetBiggestRole(IList<string> roles)
        {
            if (roles.Contains(MyRoles.admin))
                return MyRoles.admin;

            if (roles.Contains(MyRoles.manager))
                return MyRoles.manager;

            if (roles.Contains(MyRoles.client))
                return MyRoles.client;

            if (roles.Contains(MyRoles.restricted))
                return MyRoles.restricted;

            if (roles.Contains(MyRoles.unverfied))
                return MyRoles.unverfied;

            return "";

        }
        public async Task<List<string>> GetUserRoles(ApplicationUser user)
        {
            var role = await mUserManager.GetRolesAsync(user);
            return role.ToList();
        }
        public async Task<string> GetUserRole(ApplicationUser user)
        {
            var role = await GetUserRoles(user);
            return GetBiggestRole(role);
        }
        public async Task<bool> UserHasRole(ApplicationUser user, string role)
        {
            var results = await mUserManager.IsInRoleAsync(user, role);
            return results;
        }
        public async Task<bool> AddRoleToUser(ApplicationUser user, string roleName, bool AutoCreate = false)
        {
            var hasRole = await UserHasRole(user, roleName);
            // if user doesn't has the role
            if (hasRole == false)
            {
                //if role exsist
                if (await RoleExsists(roleName))
                {
                    var res = await mUserManager.AddToRoleAsync(user, roleName);
                    return res.Succeeded;
                }
                //if role doesn't exsist
                else
                {
                    // if auto create is true
                    if (AutoCreate)
                    {
                        await _CreateRole(roleName);
                        var res = await mUserManager.AddToRoleAsync(user, roleName);
                        return res.Succeeded;
                    }
                    // if auto create is false
                    else
                    {
                        return false;
                    }
                }
            }
            // if User already has role
            else
            {
                return false;
            }
        }
        public async Task<bool> RemoveRoleFromUser(ApplicationUser user, string roleName)
        {
            var hasRole = await UserHasRole(user, roleName);
            // if user has the role
            if (hasRole == true)
            {
                //if role exsist
                if (await RoleExsists(roleName))
                {
                    var res = await mUserManager.RemoveFromRoleAsync(user, roleName);
                    return res.Succeeded;
                }
                // if role doesn't exsits
                return false;
            }
            // if User dosn't already the role
            else
            {
                return true;
            }
        }
        public async Task<bool> RemoveAllRolesFromUser(ApplicationUser user)
        {
            var UserRoles = await GetUserRoles(user);
            // if user has the role
            if (UserRoles.Count > 0)
            {
                var res = await mUserManager.RemoveFromRolesAsync(user, UserRoles);
                return res.Succeeded;
            }
            // if User dosn't already the role
            else
            {
                return true;
            }
        }
        #endregion

        #region Email Verfication Methods
        public async Task<SendEmailResponse> sendEmailVerfication(string userId, string host, string urlpath, bool force = false)
        {
            var user = await GetUserById(userId);
            if (user == null)
                return null;

            SendEmailResponse results = null;
            try
            {
                results = await sendVerfication(user, host, urlpath, force);
            }
            catch (CoreUserAppException ex)
            {
                if (Debugger.IsAttached)
                    Debugger.Break();
                throw ex;
            }
            return results;

        }
        public async Task<IdentityResult> VerifyEmailAsync(string userId, string emailToken)
        {
            var user = await mUserManager.FindByIdAsync(userId);

            if (user == null)
                throw new CoreUserAppException("User not found");
            emailToken = M.Base64Decode(emailToken);
            // Verify the email token
            var result = await mUserManager.ConfirmEmailAsync(user, emailToken);
            if (result.Succeeded)
            {
                try
                {

                    await mUserManager.RemoveFromRoleAsync(user, MyRoles.unverfied);
                    await mUserManager.AddToRoleAsync(user, MyRoles.client);
                }
                catch (Exception ex)
                {
                    if (Debugger.IsAttached)
                        Debugger.Break();
                    throw ex;
                }
            }
            return result;
        }
        #endregion

        #region Get User and Claim
        public async Task<ApplicationUser> GetUserById(string userId)
        {
            var user = await mUserManager.FindByIdAsync(userId);
            return user;
        }
        public async Task<ApplicationUser> GetUserByUsername(string username)
        {
            var user = await mUserManager.FindByNameAsync(username);
            return user;
        }
        public async Task<ApplicationUser> GetUserByEmail(string email)
        {
            var user = await mUserManager.FindByEmailAsync(email);
            return user;
        }
        public async Task<_IdentityUserDto> GetUserById_includeRoleAsync(string userId)
        {
            var user = await mUserManager.FindByIdAsync(userId);
            var role = await GetUserRoles(user);
            // Return token to user
            var userDto = new _IdentityUserDto
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                role = GetBiggestRole(role),
                UserName = user.UserName,
                token = JwtToken.GenerateJwtToken(user, role.ToList(), userAppSettings)
            };
            return userDto;
        }
        public Claim FindClaim(IEnumerable<Claim> Eclaims, string ClaimType)
        {
            var claims = Eclaims.ToList();
            for (int i = 0; i < claims.Count; i++)
            {
                var claim = claims[i];
                if (claim.Type == ClaimType)
                {
                    return claim;
                }

            }
            return null;
        }
        public Claim FindClaimNameIdentifier(IEnumerable<Claim> Eclaims)
        {
            return FindClaim(Eclaims, ClaimTypes.NameIdentifier);

        }
        #endregion

        #region private Methods
        private string CreateUrlFromCode(string host, string urlpath, string VerficationCode, string userid)
        {
            var url = $"{host}{urlpath}?Id={HttpUtility.UrlEncode(userid)}&verCode={HttpUtility.UrlEncode(VerficationCode)}";
            return url;
        }
        private async Task<SendEmailResponse> sendVerfication(ApplicationUser user, string host, string urlpath, bool force = false)
        {
            if (user == null)
                throw new CoreUserAppException("Empty User,Please contact site adminstrator");

            if (user.EmailConfirmed == true && force == false)
                throw new CoreUserAppException("Email Already Confirmed");

            var emailVerificationCode = await mUserManager.GenerateEmailConfirmationTokenAsync(user);

            if (String.IsNullOrEmpty(emailVerificationCode))
                throw new CoreUserAppException("No verfication Code generated");
            emailVerificationCode = M.Base64Encode(emailVerificationCode);
            SendEmailResponse results = null;

            var ToName = user.NormalizedUserName;
            var ToEmail = user.Email.ToLower();
            var ConfermationUrl = CreateUrlFromCode(host, urlpath, emailVerificationCode, user.Id);

            try
            {
                EmailSettings emailSettings = new EmailSettings();
                emailSettings = userAppSettings.emailSettings;
                emailSettings.ToName = ToName;
                emailSettings.ToEmail = ToEmail;
                emailSettings.ButtonUrl = ConfermationUrl;

                results = await verificationEmail.SendUserVerificationEmailAsync(emailSettings);
            }
            catch (Exception ex)
            {
                if (Debugger.IsAttached)
                    Debugger.Break();
                throw new CoreUserAppException(ex.Message);
            }
            return results;

        }
        #endregion

        #region Roles Creating
        private async Task _CreateRole(string name)
        {
            var role = new IdentityRole();
            role.Name = name;
            try
            {
                var results = await roleManager.CreateAsync(role);
            }
            catch (Exception ex)
            {

                throw ex;
            }
        }
        private async Task<bool> RoleExsists(string roleName)
        {
            bool exsists;
            try
            {
                exsists = await roleManager.RoleExistsAsync(roleName);

            }
            catch (Exception ex)
            {
                return false;
            }
            return exsists;
        }
        private async Task CreateDefaultRoles()
        {
            if (!await RoleExsists(MyRoles.admin))
                await _CreateRole(MyRoles.admin);

            if (!await RoleExsists(MyRoles.client))
                await _CreateRole(MyRoles.client);

            if (!await RoleExsists(MyRoles.manager))
                await _CreateRole(MyRoles.manager);

            if (!await RoleExsists(MyRoles.restricted))
                await _CreateRole(MyRoles.restricted);

            if (!await RoleExsists(MyRoles.unverfied))
                await _CreateRole(MyRoles.unverfied);
        }
        #endregion

        //Start region
        #region StartRegion
        /*
        public async Task Start()
        {
            //Create Roles
            await CreateDefaultRoles();
            //Create admin
            await CreateAdmin();
        }
        */
        /*
        #region Create Admin
        private async Task CreateAdmin()
        {
            var adminUesr = await mUserManager.FindByEmailAsync(appSettings.adminInfo.email);
            if (adminUesr == null)
            {
                var user = new ApplicationUser()
                {
                    FirstName = appSettings.adminInfo.firstName,
                    LastName = appSettings.adminInfo.lastName,
                    UserName = appSettings.adminInfo.username,
                    Email = appSettings.adminInfo.email,
                    EmailConfirmed = true
                };
                var password = appSettings.adminInfo.password;

                var identityResult = await mUserManager.CreateAsync(user, password);

                if (identityResult.Succeeded)
                {
                    var AdminUser = await mUserManager.FindByEmailAsync(appSettings.adminInfo.email);
                    // adding admin role to admin user
                    await AddRoleToUser(AdminUser, MyRoles.admin);
                }
                else
                {
                    throw new CoreUserAppException("Couldn't create admin");
                }
            }//if
            var biggestrole =await GetUserRole(adminUesr);
            if (biggestrole!=MyRoles.admin)
            {
                var AdminUser = await mUserManager.FindByEmailAsync(appSettings.adminInfo.email);
                await mUserManager.AddToRoleAsync(AdminUser, MyRoles.admin);
            }
        }
        #endregion
        */
        #endregion

        #endregion
    }
}