using MLiberary;
using System;
using System.Collections.Generic;
using System.Text;

namespace CoreUserIdentity.Models.OAuth
{
    public class RegisterLoginResults
    {
        public _IdentityUserDto User { get; set; }
        public string operation { get; set; } = null;
        public string errors { get; set; } = null;
        public string errorsDescription { get; set; } = null;
        public bool isSuccessful => M.isNull(errors) ? true : false;
    }
}
