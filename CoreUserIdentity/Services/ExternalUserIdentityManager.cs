using CoreUserIdentity._UserIdentity;
using CoreUserIdentity.Helpers;
using CoreUserIdentity.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using MLiberary;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using CoreUserIdentity._UserIdentity.Models.Facebook;
using CoreUserIdentity._UserIdentity.Models.Google;
using CoreUserIdentity._UserIdentity.Models.OAuth;

namespace CoreUserIdentity._UserIdentity
{
    public interface IExternalUserIdentityManager<ApplicationUser, TDbContext>
    {
        #region External Registration
        Task UpdateExternalLoginInfo(ApplicationUser CheckUser, ExternalLogin externalLogin);
        Task<_IdentityUserDto> LoginWithProvider(string userId, string providername);
        Task<_IdentityUserDto> RegisterWithProvider(ExternalUserData userDataObj);
        Task<_IdentityUserDto> LoginOrRegisterExternal(ExternalUserData userDataObj);
        #endregion

        #region Facebook OAuth flow
        Task<ExternalUserData> ExcuteOAuth_CodeFlow_facebook(string client_id, string client_secret, string code, string redirecturl);

        // Get FaceBook App access token
        Task<FBDefaulAccessToken> RequestAppAccessToken(string client_secret, string client_id);


        // Exchange code for user token
        Task<FBDefaulAccessToken> RequestUserToken(string client_secret, string client_id, string code, string redirect_uri);

        // Verify User Token
        Task<FBAppDebug> RequestVerifyUserAccessToken(string appToken, string userToken);

        // Exchange Short lived token for long lived token
        Task<FBDefaulAccessToken> RequestLongLivedToken(string client_secret, string client_id, string userToken);

        // Get user Data
        Task<FacebookUserData> RequestFBUserData(string accessToken, string fields = "id,email,first_name,last_name,name,gender,locale,birthday,picture");

        // Get user Picture
        Task<FacebookPictureData> RequestUserPicture(string user_id, string type = "large");
        #endregion

        #region Google OAuth flow
        Task<ExternalUserData> ExcuteOAuth_CodeFlow_google(string client_id, string client_secret, string code, string redirect_uri);

        Task<GooglePlusAccessToken> GoogleRequestUserToken(string client_id, string client_secret, string code, string redirect_uri);

        Task<GoogleUserData> GoogleRequestUserInfo(string access_token);
        #endregion

    }
    public class ExternalUserIdentityManager<ApplicationUser, TDbContext> : IExternalUserIdentityManager<ApplicationUser, TDbContext>
        where ApplicationUser : MyIdentityUser, new()
        where TDbContext : IdentityDbContext<ApplicationUser>
    {
        #region Private Members
        private IUserIdentityManager<ApplicationUser, TDbContext> MyIdentityManager;
        private static readonly HttpClient Client = new HttpClient();
        #endregion
        #region Constructor
        public ExternalUserIdentityManager(IUserIdentityManager<ApplicationUser, TDbContext> _MyIdentityManager)
        {
            MyIdentityManager = _MyIdentityManager;
        }
        #endregion

        #region External Registration
        public async Task UpdateExternalLoginInfo(ApplicationUser CheckUser, ExternalLogin externalLogin)
        {
            CheckUser = await MyIdentityManager.GetUser_IncludeExternalLogins(CheckUser.Id);
            // if there is no provider
            if (M.isNull(CheckUser.ExternalLogin))
            {
                CheckUser.ExternalLogin = externalLogin;
                await MyIdentityManager.StrongUpdateAsync(CheckUser);

            }
            else
            {
                // if ther is a provider
                var hasCurrentProvider = CheckUser.ExternalLogin.LoginProviderName == externalLogin.LoginProviderName;
                //if current provider is the registered provider
                if (hasCurrentProvider)
                {
                }
                // if the current provider is not the registered provider
                else
                {
                    // TODO: add multiple providers support
                }
            }
        }

        public async Task<_IdentityUserDto> LoginWithProvider(string userId, string providername)
        {
            var getuser = await MyIdentityManager.GetUser_IncludeExternalLogins(userId);
            if (!M.isNull(getuser.ExternalLogin))
            {
                // check that the provider is correct

                var isCorrectProvider = getuser.ExternalLogin.LoginProviderName == providername;
                if (isCorrectProvider)
                {
                    var userDto = await MyIdentityManager.LogInWithoutPassword(getuser.UserName);
                    return userDto;
                }
                else
                {
                    throw new CoreUserAppException("provider doesn't exsist");
                }
            }
            else
            {
                throw new CoreUserAppException("provider doesn't exsist");
            }
        }

        public async Task<_IdentityUserDto> RegisterWithProvider(ExternalUserData userDataObj)
        {
            var FirstName = userDataObj.first_name;
            var LastName = userDataObj.last_name;
            var Email = userDataObj.email;
            var PictureUrl = userDataObj.PictureUrl;
            var FacebookId = userDataObj.id;
            var accesstoken = userDataObj.accessToken;

            // Register User
            var providerData = new ExternalLogin()
            {
                AccessToken = accesstoken,
                ProviderUserId = FacebookId.ToString(),
                LoginProviderName = userDataObj.providername,

            };
            ApplicationUser registerObj = new ApplicationUser()
            {
                Email = Email,
                FirstName = FirstName,
                LastName = LastName,
                UserName = Email,
                PictureUrl = PictureUrl,
                ExternalLogin = providerData
            };
            try
            {
                var registerdUser = await MyIdentityManager.StrongRegisterAsync(registerObj);
                var roles = await MyIdentityManager.GetUserRoles(registerdUser);
                _IdentityUserDto RegisteredUserDto = await MyIdentityManager.ApplicationUser_ToUserDto(registerdUser, roles);
                return RegisteredUserDto;

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<_IdentityUserDto> LoginOrRegisterExternal(ExternalUserData userDataObj)
        {
            // Check if user Registered 
            ApplicationUser CheckUser = await MyIdentityManager.GetUserByEmail(userDataObj.email);
            // if user already exsists
            if (!M.isNull(CheckUser))
            {
                try
                {
                    var userDto = await LoginWithProvider(CheckUser.Id, userDataObj.providername);
                    return userDto;

                }
                catch (Exception ex)
                {
                    if (Debugger.IsAttached)
                        Debugger.Break();
                    throw new CoreUserAppException("Email Already registered, please login with login info");
                }
            }
            // if user is not registered
            else
            {
                try
                {
                    _IdentityUserDto RegisteredUserDto = await RegisterWithProvider(userDataObj);
                    return RegisteredUserDto;
                }
                catch (Exception ex)
                {
                    if (Debugger.IsAttached)
                        Debugger.Break();
                    throw new CoreUserAppException("Email registeration error, please contact support");
                }
            }
        }
        #endregion

        #region Facebook OAuth flow
        public async Task<ExternalUserData> ExcuteOAuth_CodeFlow_facebook(string client_id, string client_secret, string code, string redirecturl)
        {
            if (string.IsNullOrWhiteSpace(client_id) || string.IsNullOrWhiteSpace(client_secret)
                || string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(redirecturl))
            {
                throw new CoreUserAppException("App Authenticatio problem");
            }
            // Generate App Token
            var apptokenObj = await RequestAppAccessToken(client_secret, client_id);
            if (M.isNull(apptokenObj) || !apptokenObj.isSuccessful)
                throw new CoreUserAppException("App Authenticatio problem");
            var apptoken = apptokenObj.access_token;
            // get user access token
            var usertokenObj = await RequestUserToken(client_secret, client_id, code, redirecturl);
            if (M.isNull(usertokenObj) || !usertokenObj.isSuccessful)
                throw new CoreUserAppException("App Authenticatio problem");

            string usertoken = usertokenObj.access_token;

            /*
            // Validate Token
            var Tokenvalidation = await VerifyUserAccessToken(apptoken, usertoken);
            if (M.isNull(Tokenvalidation) || !Tokenvalidation.data.is_valid  )
                return BadRequest("App Authenticatio problem");
            */

            ///// Authenticated

            // Get user Data
            var userDataObj = await RequestFBUserData(usertoken);
            if (M.isNull(userDataObj) || !userDataObj.isSuccessful)
                throw new CoreUserAppException("App Authenticatio problem");

            // Get User Picture
            var userPictureObj = await RequestUserPicture(userDataObj.id.ToString());
            userDataObj.Picture = userPictureObj;

            ExternalUserData externalUserData = new ExternalUserData
            {
                accessToken = usertoken,
                email = userDataObj.email,
                error = null,
                first_name = userDataObj.first_name,
                gender = userDataObj.gender,
                id = userDataObj.id.ToString(),
                last_name = userDataObj.last_name,
                locale = userDataObj.last_name,
                name = userDataObj.name,
                link = $"https://www.facebook.com/profile.php?id={userDataObj.id}",
                PictureUrl = userDataObj.Picture.data.url,
                providername = "facebook"
            };
            return externalUserData;
        }

        // Get FaceBook App access token
        public async Task<FBDefaulAccessToken> RequestAppAccessToken(string client_secret, string client_id)
        {
            var grant_type = "client_credentials";
            var url = $"https://graph.facebook.com" + $"/oauth/access_token?client_id={client_id}&client_secret={client_secret}&grant_type={grant_type}";
            string appATokenResponse = "";

            var httpResponseMessage = await Client.GetAsync(url);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                appATokenResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                var appToken = JsonConvert.DeserializeObject<FBDefaulAccessToken>(appATokenResponse);
                return appToken;
            }
            return null;

        }

        // Exchange code for user token
        public async Task<FBDefaulAccessToken> RequestUserToken(string client_secret, string client_id, string code, string redirect_uri)
        {
            var url = $"https://graph.facebook.com" + $"/v2.8/oauth/access_token?client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri={redirect_uri}";
            var httpResponseMessage = await Client.GetAsync(url);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                string userAccessTokenResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                var LongLivedToken = JsonConvert.DeserializeObject<FBDefaulAccessToken>(userAccessTokenResponse);
                return LongLivedToken;
            }
            string ErrorRead = await httpResponseMessage.Content.ReadAsStringAsync();

            return null;
        }

        // Verify User Token
        public async Task<FBAppDebug> RequestVerifyUserAccessToken(string appToken, string userToken)
        {
            // 2. validate the user access token
            var url = $"https://graph.facebook.com" + $"/debug_token?input_token={userToken}&access_token={appToken}";
            var httpResponseMessage = await Client.GetAsync(url);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                string userAccessTokenValidationResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                var userAccessTokenValidation = JsonConvert.DeserializeObject<FBAppDebug>(userAccessTokenValidationResponse);
                return userAccessTokenValidation;
            }
            return null;
        }

        // Exchange Short lived token for long lived token
        public async Task<FBDefaulAccessToken> RequestLongLivedToken(string client_secret, string client_id, string userToken)
        {
            var grant_type = "fb_exchange_token";
            var url = $"https://graph.facebook.com" + $"/oauth/access_token?grant_type={grant_type}&client_id={client_id}&client_secret={client_secret}&fb_exchange_token={userToken}";
            var httpResponseMessage = await Client.GetAsync(url);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                string userAccessTokenValidationResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                var LongLivedToken = JsonConvert.DeserializeObject<FBDefaulAccessToken>(userAccessTokenValidationResponse);
                return LongLivedToken;
            }
            return null;
        }

        // Get user Data
        public async Task<FacebookUserData> RequestFBUserData(string accessToken, string fields = "id,email,first_name,last_name,name,gender,locale,birthday,picture")
        {
            var url = $"https://graph.facebook.com" + $"/v2.8/me?fields={fields}&access_token={accessToken}";
            var httpResponseMessage = await Client.GetAsync(url);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                string FBUserDataResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                var FBUserData = JsonConvert.DeserializeObject<FacebookUserData>(FBUserDataResponse);
                return FBUserData;
            }
            return null;
        }
        
        // Get user Picture
        public async Task<FacebookPictureData> RequestUserPicture(string user_id, string type = "large")
        {
            var url = "https://graph.facebook.com" + $"/{user_id}/picture?type={type}&redirect=false";
            var httpResponseMessage = await Client.GetAsync(url);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                string FBUserPictureResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                var FBUserPicture = JsonConvert.DeserializeObject<FacebookPictureData>(FBUserPictureResponse);
                return FBUserPicture;
            }
            return null;

        }
        #endregion

        #region Google OAuth flow
        public async Task<ExternalUserData> ExcuteOAuth_CodeFlow_google(string client_id, string client_secret, string code, string redirect_uri)
        {
            GooglePlusAccessToken googlePlusAccessToken = await GoogleRequestUserToken(client_id, client_secret, code, redirect_uri);
            if (M.isNull(googlePlusAccessToken) || string.IsNullOrWhiteSpace(googlePlusAccessToken.access_token) || !googlePlusAccessToken.isSuccessful)
            {
                throw new CoreUserAppException("App Authenticatio problem");
            }
            string usertoken = googlePlusAccessToken.access_token;
            GoogleUserData userDataObj = await GoogleRequestUserInfo(usertoken);
            if (M.isNull(googlePlusAccessToken))
            {
                throw new CoreUserAppException("App Authenticatio problem");
            }
            ExternalUserData externalUserData = new ExternalUserData
            {
                accessToken = usertoken,
                email = userDataObj.email,
                error = null,
                first_name = userDataObj.given_name,
                gender = userDataObj.gender,
                id = userDataObj.id,
                last_name = userDataObj.family_name,
                locale = userDataObj.locale,
                name = userDataObj.name,
                link = userDataObj.link,
                PictureUrl = userDataObj.picture,
                providername = "google"
            };
            return externalUserData;
        }

        public async Task<GooglePlusAccessToken> GoogleRequestUserToken(string client_id, string client_secret, string code, string redirect_uri)
        {
            var grant_type = "authorization_code";
            var url = $"https://accounts.google.com/o/oauth2/token" + $"?code={code}&client_id={client_id}&client_secret={client_secret}&redirect_uri={redirect_uri}&grant_type={grant_type}";
            string appATokenResponse = "";
            GooglePlusAccessToken appToken;
            HttpContent httpContent = null;
            var httpResponseMessage = await Client.PostAsync(url, httpContent);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                appATokenResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                appToken = JsonConvert.DeserializeObject<GooglePlusAccessToken>(appATokenResponse);
                return appToken;
            }
            appATokenResponse = await httpResponseMessage.Content.ReadAsStringAsync();
            appToken = JsonConvert.DeserializeObject<GooglePlusAccessToken>(appATokenResponse);
            return appToken;
        }

        public async Task<GoogleUserData> GoogleRequestUserInfo(string access_token)
        {
            var grant_type = "authorization_code";
            var url = "https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + access_token;
            string appATokenResponse = "";
            GoogleUserData googleUser;
            var httpResponseMessage = await Client.GetAsync(url);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                appATokenResponse = await httpResponseMessage.Content.ReadAsStringAsync();
                googleUser = JsonConvert.DeserializeObject<GoogleUserData>(appATokenResponse);
                return googleUser;
            }
            appATokenResponse = await httpResponseMessage.Content.ReadAsStringAsync();
            googleUser = JsonConvert.DeserializeObject<GoogleUserData>(appATokenResponse);
            return googleUser;
        }
        #endregion
    }
}
