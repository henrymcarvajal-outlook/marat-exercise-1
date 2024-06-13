namespace WebNet4_8.App_Start.OidcSecurity
{
    public class AccessTokenResponse
    {
        public string AccessToken { get; set; }

        public string RefreshToken { get; set; }

        public string TokenType { get; set; }

        public int ExpiresIn { get; set; }
    }
}