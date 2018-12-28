using System;
using System.Globalization;

namespace CoreUserIdentity.Helpers
{
    public class CoreUserAppException : Exception
    {
        public CoreUserAppException() : base() { }
        public CoreUserAppException(string message) : base(message) { }

        public CoreUserAppException(string message, Exception inner) : base(message, inner) { }

        public CoreUserAppException(string message, params object[] args)
            : base(String.Format(CultureInfo.CurrentCulture, message, args))
        {
        }
    }
}
