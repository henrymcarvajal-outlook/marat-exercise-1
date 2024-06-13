using System;
using System.Net.Http.Headers;
using System.Text;

namespace WebNet4_8.App_Start.OidcSecurity
{
    public class BasicAuthenticationHeaderValue : AuthenticationHeaderValue
    {
        public BasicAuthenticationHeaderValue(string userName, string password)
            : base("Basic", EncodeCredential(userName, password))
        {
        }

        private static string EncodeCredential(string userName, string password)
        {
            Encoding uTF = Encoding.UTF8;
            string s = $"{userName}:{password}";
            return Convert.ToBase64String(uTF.GetBytes(s));
        }
    }
}