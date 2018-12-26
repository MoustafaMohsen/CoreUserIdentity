using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserIdentity._UserIdentity.Models.OAuth
{
    public class ExternalUserData
    {
        public string providername { get; set; }
        public string accessToken { get; set; }
        public string id { get; set; }
        public string email { get; set; }
        public string name { get; set; }
        //[JsonProperty("first_name")]
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string gender { get; set; }
        public string locale { get; set; }
        public string PictureUrl { get; set; }
        public string link { get; set; }
        public string error { get; set; }
        public bool isSuccessful => string.IsNullOrEmpty(error) ? true : false;


    }
}
