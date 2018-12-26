using MLiberary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserIdentity._UserIdentity.Models.Google
{
    public class GooglePlusAccessToken
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string id_token { get; set; }
        public string refresh_token { get; set; }
        public string error { get; set; }
        public string error_description { get; set; }
        public bool isSuccessful => M.isNull(error) ? true : false;
    }
}
