using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserIdentity._UserIdentity.Models.Google
{
    public class GoogleUserData
    {
        public string id { get; set; }
        public string name { get; set; }
        public string given_name { get; set; }
        public string gender { get; set; }
        public string family_name { get; set; }
        public string email { get; set; }
        public string verified_email { get; set; }
        public string link { get; set; }
        public string picture { get; set; }
        public string locale { get; set; }
    }
}
