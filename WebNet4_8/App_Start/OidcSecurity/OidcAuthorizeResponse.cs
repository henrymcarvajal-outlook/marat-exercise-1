namespace WebNet4_8.App_Start.OidcSecurity
{
    public class OidcAuthorizeResponse
    {
        public bool IsError { get; internal set; }

        public string Error { get; internal set; }

        public string Code { get; internal set; }

        public string State { get; internal set; }
    }
}