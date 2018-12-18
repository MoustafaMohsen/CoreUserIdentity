using Microsoft.AspNetCore.Identity;

namespace CoreUserIdentity.Models
{
    public class MyIdentityUser : IdentityUser
    {
        public string FirstName { get; internal set; }
        public string LastName { get; internal set; }
    }
}
