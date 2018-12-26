using MLiberary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserIdentity._UserIdentity.Models.Facebook
{
    public class FBDefaulAccessToken
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public FBError error { get; set; }
        public bool isSuccessful => M.isNull(error) ? true : false;
    }
}
