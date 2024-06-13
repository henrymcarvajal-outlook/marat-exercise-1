using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace WebNet4_8.App_Start.OidcSecurity
{

    public class OidcClient
    {
        public static Uri CreateAuthorizeUrl(Uri authorizeEndpoint, Uri redirectUri, string clientId, string scopes, string state, string responseType = "code")
        {
            string text = $"?client_id={WebUtility.UrlEncode(clientId)}&scope={WebUtility.UrlEncode(scopes)}&redirect_uri={WebUtility.UrlEncode(redirectUri.AbsoluteUri)}&state={WebUtility.UrlEncode(state)}&response_type={responseType}";
            return new Uri(authorizeEndpoint.AbsoluteUri + text);
        }

        public static OidcAuthorizeResponse ParseAuthorizeResponse(NameValueCollection query)
        {
            OidcAuthorizeResponse oidcAuthorizeResponse = new OidcAuthorizeResponse
            {
                Error = query["error"],
                Code = query["code"],
                State = query["state"]
            };
            OidcAuthorizeResponse oidcAuthorizeResponse2 = oidcAuthorizeResponse;
            oidcAuthorizeResponse2.IsError = !string.IsNullOrWhiteSpace(oidcAuthorizeResponse2.Error);
            return oidcAuthorizeResponse2;
        }

        public static async Task<OidcTokenResponse> CallTokenEndpointAsync(Uri tokenEndpoint, Uri redirectUri, string code, string clientId, string clientSecret, string scopes)
        {
            HttpClient client = new HttpClient
            {
                BaseAddress = tokenEndpoint
            };
            client.SetBasicAuthentication(clientId, clientSecret);

            Dictionary<string, string> parameter = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", redirectUri.AbsoluteUri },
                { "scope", scopes}
            };
            HttpResponseMessage response = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(parameter));
            response.EnsureSuccessStatusCode();
            JObject jObject = JObject.Parse(await response.Content.ReadAsStringAsync());
            JObject json = jObject;
            return json.ToObject<OidcTokenResponse>();
        }

        public static OidcTokenResponse RefreshAccessToken(Uri tokenEndpoint, string clientId, string clientSecret, string refreshToken)
        {
            OAuth2Client oAuth2Client = new OAuth2Client(tokenEndpoint, clientId, clientSecret);
            AccessTokenResponse accessTokenResponse = oAuth2Client.RequestAccessTokenRefreshToken(refreshToken);
            OidcTokenResponse oidcTokenResponse = new OidcTokenResponse
            {
                AccessToken = accessTokenResponse.AccessToken,
                ExpiresIn = accessTokenResponse.ExpiresIn,
                TokenType = accessTokenResponse.TokenType,
                RefreshToken = refreshToken
            };
            return oidcTokenResponse;
        }

        //Implement a method to automatically refresh the access token before access token expires
        public static async Task<OidcTokenResponse> RefreshAccessTokenAsync(Uri tokenEndpoint, string clientId, string clientSecret, string refreshToken)
        {
           

            HttpClient client = new HttpClient
            {
                BaseAddress = tokenEndpoint
            };
            client.SetBasicAuthentication(clientId, clientSecret);
            Dictionary<string, string> parameter = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken }
            };
            HttpResponseMessage response = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(parameter));
            response.EnsureSuccessStatusCode();
            JObject jObject = JObject.Parse(await response.Content.ReadAsStringAsync());
            JObject json = jObject;
            return json.ToObject<OidcTokenResponse>();
        }


        //public static IEnumerable<Claim> ValidateIdentityToken(string token, string issuer, string audience, X509Certificate2 signingCertificate, X509CertificateValidator certificateValidator = null)
        //{
        //    if (certificateValidator == null)
        //    {
        //        certificateValidator = X509CertificateValidator.None;
        //    }

        //    SecurityTokenHandlerConfiguration securityTokenHandlerConfiguration = new SecurityTokenHandlerConfiguration();
        //    securityTokenHandlerConfiguration.CertificateValidator = certificateValidator;
        //    SecurityTokenHandlerConfiguration configuration = securityTokenHandlerConfiguration;
        //    var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        //    jwtSecurityTokenHandler.Configuration = configuration;
        //    JwtSecurityTokenHandler jwtSecurityTokenHandler2 = jwtSecurityTokenHandler;
        //    TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
        //    tokenValidationParameters.ValidIssuer = issuer;
        //    tokenValidationParameters.AllowedAudience = audience;
        //    tokenValidationParameters.SigningToken = new X509SecurityToken(signingCertificate);
        //    TokenValidationParameters tokenValidationParameters2 = tokenValidationParameters;
        //    return jwtSecurityTokenHandler2.ValidateToken(token, tokenValidationParameters2).Claims;
        //}

        public static async Task<IEnumerable<Claim>> GetUserInfoClaimsAsync(Uri userInfoEndpoint, string accessToken)
        {
            HttpClient client = new HttpClient
            {
                BaseAddress = userInfoEndpoint
            };
            client.SetBearerToken(accessToken);
            HttpResponseMessage response = await client.GetAsync("");
            response.EnsureSuccessStatusCode();
            Dictionary<string, string> dictionary = null;// await response.Content.ReadAsAsync<Dictionary<string, string>>();
            List<Claim> claims = new List<Claim>();
            foreach (KeyValuePair<string, string> item in dictionary)
            {
                if (item.Value.Contains(','))
                {
                    string[] array = item.Value.Split(',');
                    foreach (string value in array)
                    {
                        claims.Add(new Claim(item.Key, value));
                    }

                    if (1 == 0)
                    {
                    }
                }
                else
                {
                    claims.Add(new Claim(item.Key, item.Value));
                }
            }

            return claims;
        }
    }
}