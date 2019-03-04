using MLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserIdentity._UserIdentity.Models.Facebook
{
    public class FBAppDebugData
    {
        public string app_id { get; set; }
        public string type { get; set; }
        public string application { get; set; }
        public int data_access_expires_at { get; set; }
        public int expires_at { get; set; }
        public bool is_valid { get; set; }
        public List<string> scopes { get; set; }
        public string user_id { get; set; }
        public FBError error { get; set; }
        public bool isSuccessful => M.isNull(error) ? true : false;
    }


    public class FBAppDebug
    {
        public FBAppDebugData data { get; set; }
    }
}
