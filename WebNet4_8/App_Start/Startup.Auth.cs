using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;
using WebNet4_8.App_Start.OidcSecurity;

namespace WebNet4_8
{
    public partial class Startup
    {
        private static readonly string clientId = ConfigurationManager.AppSettings[Constants.ClientId];
        private static readonly string aadInstance = EnsureTrailingSlash(ConfigurationManager.AppSettings[Constants.AzureAdInstance]);
        private static readonly string tenantId = ConfigurationManager.AppSettings[Constants.TenantId];
        private static readonly string postLogoutRedirectUri = ConfigurationManager.AppSettings[Constants.PostLogoutRedirectUri];
        private static readonly string authority = aadInstance + tenantId;
        private static readonly string scopes = ConfigurationManager.AppSettings[Constants.Scopes];
        private static readonly string redirectUri = ConfigurationManager.AppSettings[Constants.RedirectUri];
        private static readonly string clientSecret = ConfigurationManager.AppSettings[Constants.ClientSecretEnvironmentVariable] ?? ConfigurationManager.AppSettings[Constants.ClientSecret];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = Constants.ApplicationCookie
            });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = authority,
                    PostLogoutRedirectUri = postLogoutRedirectUri,
                    Scope = scopes,
                    ResponseType = Constants.ResponseType,
                    SignInAsAuthenticationType = Constants.ApplicationCookie,
                    SaveTokens = true,

                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        SecurityTokenValidated = (context) =>
                        {
                            string name = context.AuthenticationTicket.Identity.FindFirst(Constants.Name).Value;
                            context.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Name, name, string.Empty));

                            RefreshAccessToken(context);

                            return Task.FromResult(0);
                        },

                        AuthorizationCodeReceived = async (context) =>
                        {
                            var requestResponse = await OidcClient.CallTokenEndpointAsync(new Uri(authority + Constants.TokenEndpoint),
                                new Uri(redirectUri),
                                context.Code,
                                clientId,
                                clientSecret,
                                scopes);

                            var identity = context.AuthenticationTicket.Identity;
                            identity.AddClaim(new Claim(Constants.AccessToken, requestResponse.AccessToken));
                            identity.AddClaim(new Claim(Constants.IdToken, requestResponse.IdentityToken));
                            identity.AddClaim(new Claim(Constants.RefereshToken, requestResponse.RefreshToken));

                            context.AuthenticationTicket = new AuthenticationTicket(
                                identity, context.AuthenticationTicket.Properties);
                        },
                        RedirectToIdentityProvider = notification =>
                        {
                            if (notification.ProtocolMessage.RequestType != OpenIdConnectRequestType.Logout)
                            {
                                return Task.FromResult(0);
                            }

                            notification.ProtocolMessage.IdTokenHint =
                                notification.OwinContext.Authentication.User.FindFirst(Constants.IdToken).Value;

                            return Task.FromResult(0);
                        }
                    }
                });

        }

        private static void RefreshAccessToken(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            var identity = context.AuthenticationTicket.Identity;

            // Check if the access token is expired
            var expiresOnValue = identity.FindFirst(Constants.ExpiresOn)?.Value;
            if (expiresOnValue == null)
            {
                // Handle the case where the expires_on claim is missing
                return;
            }

            if (!long.TryParse(expiresOnValue, out var expiresOnSeconds))
            {
                // Handle the case where the expires_on value cannot be parsed as a long
                return;
            }

            var expiresOn = FromUnixTimeSeconds(expiresOnSeconds);

            // Define a clock skew
            var clockSkew = TimeSpan.FromMinutes(3);

            if (expiresOn.Add(clockSkew) < DateTime.UtcNow)
            {
                // The access token is expired. Use the refresh token to get a new one.
                var refreshToken = identity.FindFirst(Constants.RefereshToken)?.Value;
                if (refreshToken == null)
                {
                    // Handle the case where the refresh_token claim is missing
                    return;
                }

                var requestResponse = OidcClient.RefreshAccessToken(new Uri(authority + Constants.TokenEndpoint),
                    clientId, clientSecret, refreshToken);

                // Update the ClaimsIdentity with the new access token and refresh token
                identity.RemoveClaim(identity.FindFirst(Constants.AccessToken));
                identity.AddClaim(new Claim(Constants.AccessToken, requestResponse.AccessToken));

                identity.RemoveClaim(identity.FindFirst(Constants.RefereshToken));
                identity.AddClaim(new Claim(Constants.RefereshToken, requestResponse.RefreshToken));
            }
        }


        public static DateTime FromUnixTimeSeconds(long seconds)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddSeconds(seconds);
        }

        private static string EnsureTrailingSlash(string value)
        {
            if (value == null)
            {
                value = string.Empty;
            }

            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                return value + "/";
            }

            return value;
        }
    }
}
