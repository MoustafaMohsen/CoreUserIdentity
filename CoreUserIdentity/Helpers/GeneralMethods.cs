using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace CoreUserIdentity.Helpers
{
    public static class GeneralMethods
    {
        public static bool IsEmail(string email)
        {
            string emailPattern = @"^\s*[\w\-\+_']+(\.[\w\-\+_']+)*\@[A-Za-z0-9]([\w\.-]*[A-Za-z0-9])?\.[A-Za-z\.]*[A-Za-z]$";
            return Regex.IsMatch(email, emailPattern);
        }

    }
}
