using System;
using System.Configuration;
using System.Web.Mvc;

namespace WebNet4_8.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            string clientId = ConfigurationManager.AppSettings[Constants.ClientId];
            string authority = ConfigurationManager.AppSettings[Constants.AzureAdInstance] + ConfigurationManager.AppSettings[Constants.TenantId];
            string clientSecret = ConfigurationManager.AppSettings[Constants.ClientSecretEnvironmentVariable] ?? ConfigurationManager.AppSettings[Constants.ClientSecret];

            if (User.Identity is System.Security.Claims.ClaimsIdentity claimsIdentity)
            {
                var refreshTokenClaim = claimsIdentity.FindFirst(Constants.RefereshToken);
                if (refreshTokenClaim != null)
                {
                    var accessTokenClaim = claimsIdentity.FindFirst(Constants.AccessToken);

                    string refreshToken = refreshTokenClaim.Value;
                    var response = App_Start.OidcSecurity.OidcClient.RefreshAccessToken(new Uri(authority + Constants.TokenEndpoint), clientId, clientSecret, refreshToken);

                    var refreshedAccessTocken = response.AccessToken;

                    ViewBag.AccessTokenClaim = accessTokenClaim?.Value;
                    ViewBag.RefreshedAccessToken = refreshedAccessTocken;
                }
            }

            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}