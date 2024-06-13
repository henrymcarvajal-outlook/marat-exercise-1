using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace WebNet4_8.App_Start.OidcSecurity
{
    public class OAuth2Client
    {
        private const string tokenUri = "https://login.microsoftonline.com/ff5a6044-ffb8-488b-b31b-b039ef5df0d7/oauth2/v2.0/token";
        private readonly HttpClient _client;

        public OAuth2Client(Uri address)
        {
            _client = new HttpClient
            {
                BaseAddress = address
            };
        }

        public OAuth2Client(Uri address, string clientId, string clientSecret)
            : this(address)
        {
            _client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(clientId, clientSecret);
        }

        public static string CreateCodeFlowUrl(string endpoint, string clientId, string scope, string redirectUri, string state = null)
        {
            return CreateUrl(endpoint, clientId, scope, redirectUri, "code", state);
        }

        public static string CreateImplicitFlowUrl(string endpoint, string clientId, string scope, string redirectUri, string state = null)
        {
            return CreateUrl(endpoint, clientId, scope, redirectUri, "token", state);
        }

        private static string CreateUrl(string endpoint, string clientId, string scope, string redirectUri, string responseType, string state = null)
        {
            string text = $"{endpoint}?client_id={clientId}&scope={scope}&redirect_uri={redirectUri}&response_type={responseType}";
            if (!string.IsNullOrWhiteSpace(state))
            {
                text = $"{text}&state={state}";
            }

            return text;
        }

        public AccessTokenResponse RequestAccessTokenUserName(string userName, string password, string scope, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = _client.PostAsync("", CreateFormUserName(userName, password, scope, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            JObject json = JObject.Parse(result.Content.ReadAsStringAsync().Result);
            return CreateResponseFromJson(json);
        }

        public AccessTokenResponse RequestAccessTokenClientCredentials(string scope, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = _client.PostAsync("", CreateFormClientCredentials(scope, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            JObject json = JObject.Parse(result.Content.ReadAsStringAsync().Result);
            return CreateResponseFromJson(json);
        }

        public AccessTokenResponse RequestAccessTokenRefreshToken(string refreshToken, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = _client.PostAsync(tokenUri, CreateFormRefreshToken(refreshToken, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            JObject json = JObject.Parse(result.Content.ReadAsStringAsync().Result);
            return CreateResponseFromJson(json);
        }

        public AccessTokenResponse RequestAccessTokenCode(string code, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = _client.PostAsync("", CreateFormCode(code, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            JObject json = JObject.Parse(result.Content.ReadAsStringAsync().Result);
            return CreateResponseFromJson(json);
        }

        public AccessTokenResponse RequestAccessTokenCode(string code, Uri redirectUri, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = _client.PostAsync("", CreateFormCode(code, redirectUri, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            JObject json = JObject.Parse(result.Content.ReadAsStringAsync().Result);
            return CreateResponseFromJson(json);
        }

        public AccessTokenResponse RequestAccessTokenAssertion(string assertion, string assertionType, string scope, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = _client.PostAsync("", CreateFormAssertion(assertion, assertionType, scope, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            JObject json = JObject.Parse(result.Content.ReadAsStringAsync().Result);
            return CreateResponseFromJson(json);
        }

        protected virtual FormUrlEncodedContent CreateFormClientCredentials(string scope, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "scope", scope }
            };
            Dictionary<string, string> explicitProperties = dictionary;
            return CreateForm(explicitProperties, additionalProperties);
        }

        protected virtual FormUrlEncodedContent CreateFormUserName(string userName, string password, string scope, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "username", userName },
                { "password", password },
                { "scope", scope }
            };
            Dictionary<string, string> explicitProperties = dictionary;
            return CreateForm(explicitProperties, additionalProperties);
        }

        protected virtual FormUrlEncodedContent CreateFormRefreshToken(string refreshToken, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken }
            };
            Dictionary<string, string> explicitProperties = dictionary;
            return CreateForm(explicitProperties, additionalProperties);
        }

        protected virtual FormUrlEncodedContent CreateFormCode(string code, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code }
            };
            Dictionary<string, string> explicitProperties = dictionary;
            return CreateForm(explicitProperties, additionalProperties);
        }

        protected virtual FormUrlEncodedContent CreateFormCode(string code, Uri redirectUri, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "redirect_uri", redirectUri.AbsoluteUri },
                { "code", code }
            };
            Dictionary<string, string> explicitProperties = dictionary;
            return CreateForm(explicitProperties, additionalProperties);
        }

        protected virtual FormUrlEncodedContent CreateFormAssertion(string assertion, string assertionType, string scope, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>
            {
                { "grant_type", assertionType },
                { "assertion", assertion },
                { "scope", scope }
            };
            Dictionary<string, string> explicitProperties = dictionary;
            return CreateForm(explicitProperties, additionalProperties);
        }

        private AccessTokenResponse CreateResponseFromJson(JObject json)
        {
            AccessTokenResponse accessTokenResponse = new AccessTokenResponse
            {
                AccessToken = json["access_token"].ToString(),
                TokenType = json["token_type"].ToString(),
                ExpiresIn = int.Parse(json["expires_in"].ToString())
            };
            AccessTokenResponse accessTokenResponse2 = accessTokenResponse;
            if (json["refresh_token"] != null)
            {
                accessTokenResponse2.RefreshToken = json["refresh_token"].ToString();
            }

            return accessTokenResponse2;
        }

        //
        // Summary:
        //     FormUrlEncodes both Sets of Key Value Pairs into one form object
        //
        // Parameters:
        //   explicitProperties:
        //
        //   additionalProperties:
        private static FormUrlEncodedContent CreateForm(Dictionary<string, string> explicitProperties, Dictionary<string, string> additionalProperties = null)
        {
            return new FormUrlEncodedContent(MergeAdditionKeyValuePairsIntoExplicitKeyValuePairs(explicitProperties, additionalProperties));
        }

        //
        // Summary:
        //     Merges additional into explicit properties keeping all explicit properties intact
        //
        //
        // Parameters:
        //   explicitProperties:
        //
        //   additionalProperties:
        private static Dictionary<string, string> MergeAdditionKeyValuePairsIntoExplicitKeyValuePairs(Dictionary<string, string> explicitProperties, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> result = explicitProperties;
            if (additionalProperties != null)
            {
                result = explicitProperties.Concat(additionalProperties.Where((KeyValuePair<string, string> add) => !explicitProperties.ContainsKey(add.Key))).ToDictionary((KeyValuePair<string, string> final) => final.Key, (KeyValuePair<string, string> final) => final.Value);
            }

            return result;
        }
    }
}