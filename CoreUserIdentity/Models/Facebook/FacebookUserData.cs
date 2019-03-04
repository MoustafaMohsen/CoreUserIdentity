using MLibrary;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserIdentity._UserIdentity.Models.Facebook
{
    public class FacebookUserData
    {
        public long id { get; set; }
        public string email { get; set; }
        public string name { get; set; }
        //[JsonProperty("first_name")]
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string gender { get; set; }
        public string locale { get; set; }
        public FacebookPictureData Picture { get; set; }
        public FBError error { get; set; }
        public bool isSuccessful => M.isNull(error) ? true : false;

    }

    public class FacebookPictureData
    {

        public FacebookPicture data { get; set; }
    }

    public class FacebookPicture
    {
        public int height { get; set; }
        public int width { get; set; }
        [JsonProperty("is_silhouette")]
        public bool IsSilhouette { get; set; }
        public string url { get; set; }
    }

}
