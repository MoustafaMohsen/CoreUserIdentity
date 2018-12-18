namespace CoreUserIdentity.Models
{
    public class LoginUserDto
    {
        /// <summary>
        /// the login username or email
        /// </summary>
        public string usernameOrEmail { get; set; }

        /// <summary>
        /// the login password
        /// </summary>
        public string password { get; set; }
    }
}
