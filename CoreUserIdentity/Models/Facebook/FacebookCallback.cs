using MLiberary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserIdentity._UserIdentity.Models.Facebook
{
    public class FacebookCallback
    {
        public string access_token { get; set; }
        public int expires_in { get; set; }
        public int reauthorize_required_in { get; set; }
        public int data_access_expiration_time { get; set; }

        public FBError error { get; set; }
        public bool isSuccessful => M.isNull(error) ? true : false;

    }
}
