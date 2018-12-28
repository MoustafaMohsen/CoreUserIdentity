using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace CoreUserIdentity.Models
{
    public class MyIdentityUser : IdentityUser
    {
        [MaxLength(length: 255)]
        public string FirstName { get; internal set; }

        [MaxLength(length: 255)]
        public string LastName { get; internal set; }

        [MaxLength(length: 2083)]
        public string PictureUrl { get; set; }

        public ExternalLogin ExternalLogin { get; set; }
    }

    public class ExternalLogin{
        public string Id { get; set; }
        public string LoginProviderName { get; set; }
        public string AccessToken { get; set; }
        public string ProviderUserId { get; set; }
        public List<OtherValue> OtherUserInfo { get; set; }
    }

    public class OtherValue
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
    }
}
