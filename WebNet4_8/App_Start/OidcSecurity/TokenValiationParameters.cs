using System.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IdentityModel.Selectors;
using System.Security.Claims;

namespace WebNet4_8.App_Start.OidcSecurity
{
    public class TokenValidationParameters
    {
        //
        // Summary:
        //     Default for the maximm token size.
        //
        // Remarks:
        //     2 MB (mega bytes).
        public const int DefaultMaximumTokenSizeInBytes = 2097152;

        private string _authenticationType;

        private X509CertificateValidator _certificateValidator;

        private ReadOnlyCollection<SecurityToken> _clientDecryptionTokens = new List<SecurityToken>().AsReadOnly();

        private TimeSpan _clockSkew = DefaultClockSkew;

        private string _nameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";

        private string _roleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

        //
        // Summary:
        //     This is the fallback authenticationtype that a System.IdentityModel.Tokens.ISecurityTokenValidator
        //     will use if nothing is set.
        public static readonly string DefaultAuthenticationType = "Federation";

        //
        // Summary:
        //     Default for the clock skew.
        //
        // Remarks:
        //     300 seconds (5 minutes).
        public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromSeconds(300.0);

        //
        // Summary:
        //     Gets or sets a delegate that will be used to validate the audience of the tokens
        public AudienceValidator AudienceValidator { get; set; }

        //
        // Summary:
        //     Gets or sets the AuthenticationType when creating a System.Security.Claims.ClaimsIdentity
        //     during token validation.
        //
        // Exceptions:
        //   T:System.ArgumentNullException:
        //     if 'value' is null or whitespace.
        public string AuthenticationType
        {
            get
            {
                return _authenticationType;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException("AuthenticationType");
                }

                _authenticationType = value;
            }
        }

        //
        // Summary:
        //     Gets or sets the System.IdentityModel.Selectors.X509CertificateValidator for
        //     validating X509Certificate2(s).
        public X509CertificateValidator CertificateValidator
        {
            get
            {
                return _certificateValidator;
            }
            set
            {
                _certificateValidator = value;
            }
        }

        //
        // Summary:
        //     Gets or sets the System.Collections.ObjectModel.ReadOnlyCollection`1 that is
        //     to be used for decrypting inbound tokens.
        //
        // Exceptions:
        //   T:System.ArgumentNullException:
        //     if 'value' is null.
        public ReadOnlyCollection<SecurityToken> ClientDecryptionTokens
        {
            get
            {
                return _clientDecryptionTokens;
            }
            set
            {
                _clientDecryptionTokens = value ?? throw new ArgumentNullException(nameof(ClientDecryptionTokens));
            }
        }


        //
        // Summary:
        //     Gets or sets the clock skew to apply when validating times
        //
        // Exceptions:
        //   T:System.ArgumentOutOfRangeException:
        //     if 'value' is less than 0.
        [DefaultValue(300)]
        public TimeSpan ClockSkew
        {
            get
            {
                return _clockSkew;
            }
            set
            {
                if (value < TimeSpan.Zero)
                {
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, "IDX10100: ClockSkew must be greater than TimeSpan.Zero. value: '{0}'", new object[1] { value }));
                }

                _clockSkew = value;
            }
        }

        //
        // Summary:
        //     Gets or sets the System.IdentityModel.Tokens.SecurityKey that is to be used for
        //     validating signed tokens.
        public Action<SecurityKey> IssuerSigningKeyValidator { get; set; }

        //
        // Summary:
        //     Gets or sets the System.IdentityModel.Tokens.SecurityKey that is to be used for
        //     validating signed tokens.
        public System.IdentityModel.Tokens.SecurityKey IssuerSigningKey { get; set; }

        //
        // Summary:
        //     Gets or sets a delegate that will be used to retreive System.IdentityModel.Tokens.SecurityKey(s)
        //     used for checking signatures.
        //
        // Remarks:
        //     Each System.IdentityModel.Tokens.SecurityKey will be used to check the signature.
        //     Returning multiple key can be helpful when the System.IdentityModel.Tokens.SecurityToken
        //     does not contain a key identifier. This can occur when the issuer has multiple
        //     keys available. This sometimes occurs during key rollover.
        public IssuerSigningKeyResolver IssuerSigningKeyResolver { get; set; }

        //
        // Summary:
        //     Gets or sets the System.Collections.Generic.IEnumerable`1 that are to be used
        //     for validating signed tokens.
        public IEnumerable<System.IdentityModel.Tokens.SecurityKey> IssuerSigningKeys { get; set; }

        //
        // Summary:
        //     Gets or sets the System.IdentityModel.Tokens.SecurityToken that is used for validating
        //     signed tokens.
        public SecurityToken IssuerSigningToken { get; set; }

        //
        // Summary:
        //     Gets or sets the System.Collections.Generic.IEnumerable`1 that are to be used
        //     for validating signed tokens.
        public IEnumerable<SecurityToken> IssuerSigningTokens { get; set; }

        //
        // Summary:
        //     Gets or sets a delegate that will be used to validate the issuer of the token.
        //     The delegate returns the issuer to use.
        public IssuerValidator IssuerValidator { get; set; }

        //
        // Summary:
        //     Gets or sets a delegate that will be used to validate the lifetime of the token
        public LifetimeValidator LifetimeValidator { get; set; }

        //
        // Summary:
        //     Gets or sets the System.String passed to System.Security.Claims.ClaimsIdentity.#ctor(System.String,System.String,System.String).
        //
        //
        // Remarks:
        //     Controls the value System.Security.Claims.ClaimsIdentity.Name returns. It will
        //     return the first System.Security.Claims.Claim.Value where the System.Security.Claims.Claim.Type
        //     equals System.IdentityModel.Tokens.TokenValidationParameters.NameClaimType.
        public string NameClaimType
        {
            get
            {
                return _nameClaimType;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException("IDX10102: NameClaimType cannot be null or whitespace.");
                }

                _nameClaimType = value;
            }
        }

        //
        // Summary:
        //     Gets or sets the System.String passed to System.Security.Claims.ClaimsIdentity.#ctor(System.String,System.String,System.String).
        //
        //
        // Remarks:
        //     Controls the System.Security.Claims.Claim(s) returned from System.Security.Claims.ClaimsPrincipal.IsInRole(System.String).
        //
        //
        //     Each System.Security.Claims.Claim returned will have a System.Security.Claims.Claim.Type
        //     equal to System.IdentityModel.Tokens.TokenValidationParameters.RoleClaimType.
        public string RoleClaimType
        {
            get
            {
                return _roleClaimType;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException("IDX10103: RoleClaimType cannot be null or whitespace.");
                }

                _roleClaimType = value;
            }
        }

        //
        // Summary:
        //     Gets or sets a delegate that will be called to obtain the NameClaimType to use
        //     when creating a ClaimsIdentity when validating a token.
        public Func<SecurityToken, string, string> NameClaimTypeRetriever { get; set; }

        //
        // Summary:
        //     Gets or sets a value indicating whether tokens must have an 'expiration' value.
        [DefaultValue(true)]
        public bool RequireExpirationTime { get; set; }

        //
        // Summary:
        //     Gets or sets a value indicating whether a System.IdentityModel.Tokens.SecurityToken
        //     can be valid if not signed.
        [DefaultValue(true)]
        public bool RequireSignedTokens { get; set; }

        //
        // Summary:
        //     Gets or sets a delegate that will be called to obtain the RoleClaimType to use
        //     when creating a ClaimsIdentity when validating a token.
        public Func<SecurityToken, string, string> RoleClaimTypeRetriever { get; set; }

        //
        // Summary:
        //     Gets or sets a boolean to control if the original token is saved when a session
        //     is created. ///
        //
        // Remarks:
        //     The SecurityTokenValidator will use this value to save the orginal string that
        //     was validated.
        [DefaultValue(false)]
        public bool SaveSigninToken { get; set; }

        //
        // Summary:
        //     Gets or set the System.IdentityModel.Tokens.ITokenReplayCache that will be checked
        //     to help in detecting that a token has been 'seen' before.
        public ITokenReplayCache TokenReplayCache { get; set; }

        //
        // Summary:
        //     Gets or sets a value indicating whether the System.IdentityModel.Tokens.JwtSecurityToken.Actor
        //     should be validated.
        [DefaultValue(false)]
        public bool ValidateActor { get; set; }

        //
        // Summary:
        //     Gets or sets a boolean to control if the audience will be validated during token
        //     validation.
        [DefaultValue(true)]
        public bool ValidateAudience { get; set; }

        //
        // Summary:
        //     Gets or sets a boolean to control if the issuer will be validated during token
        //     validation.
        [DefaultValue(true)]
        public bool ValidateIssuer { get; set; }

        //
        // Summary:
        //     Gets or sets a boolean to control if the lifetime will be validated during token
        //     validation.
        [DefaultValue(true)]
        public bool ValidateLifetime { get; set; }

        //
        // Summary:
        //     Gets or sets a boolean that controls if validation of the System.IdentityModel.Tokens.SecurityKey
        //     that signed the securityToken is called.
        public bool ValidateIssuerSigningKey { get; set; }

        //
        // Summary:
        //     Gets or sets a string that represents a valid audience that will be used during
        //     token validation.
        public string ValidAudience { get; set; }

        //
        // Summary:
        //     Gets or sets the System.Collections.Generic.ICollection`1 that contains valid
        //     audiences that will be used during token validation.
        public IEnumerable<string> ValidAudiences { get; set; }

        //
        // Summary:
        //     Gets or sets a System.String that represents a valid issuer that will be used
        //     during token validation.
        public string ValidIssuer { get; set; }

        //
        // Summary:
        //     Gets or sets the System.Collections.Generic.ICollection`1 that contains valid
        //     issuers that will be used during token validation.
        public IEnumerable<string> ValidIssuers { get; set; }

        //
        // Summary:
        //     Copy constructor for System.IdentityModel.Tokens.TokenValidationParameters.
        protected TokenValidationParameters(TokenValidationParameters other)
        {
            if (other == null)
            {
                throw new ArgumentNullException("other");
            }

            AudienceValidator = other.AudienceValidator;
            _authenticationType = other._authenticationType;
            CertificateValidator = other.CertificateValidator;
            ClockSkew = other.ClockSkew;
            ClientDecryptionTokens = other.ClientDecryptionTokens;
            IssuerSigningKey = other.IssuerSigningKey;
            IssuerSigningKeyResolver = other.IssuerSigningKeyResolver;
            IssuerSigningKeys = other.IssuerSigningKeys;
            IssuerSigningKeyValidator = other.IssuerSigningKeyValidator;
            IssuerSigningToken = other.IssuerSigningToken;
            IssuerSigningTokens = other.IssuerSigningTokens;
            IssuerValidator = other.IssuerValidator;
            LifetimeValidator = other.LifetimeValidator;
            NameClaimType = other.NameClaimType;
            NameClaimTypeRetriever = other.NameClaimTypeRetriever;
            RequireExpirationTime = other.RequireExpirationTime;
            RequireSignedTokens = other.RequireSignedTokens;
            RoleClaimType = other.RoleClaimType;
            RoleClaimTypeRetriever = other.RoleClaimTypeRetriever;
            SaveSigninToken = other.SaveSigninToken;
            TokenReplayCache = other.TokenReplayCache;
            ValidateActor = other.ValidateActor;
            ValidateAudience = other.ValidateAudience;
            ValidateIssuer = other.ValidateIssuer;
            ValidateIssuerSigningKey = other.ValidateIssuerSigningKey;
            ValidateLifetime = other.ValidateLifetime;
            ValidAudience = other.ValidAudience;
            ValidAudiences = other.ValidAudiences;
            ValidIssuer = other.ValidIssuer;
            ValidIssuers = other.ValidIssuers;
        }

        //
        // Summary:
        //     Initializes a new instance of the System.IdentityModel.Tokens.TokenValidationParameters
        //     class.
        public TokenValidationParameters()
        {
            RequireExpirationTime = true;
            RequireSignedTokens = true;
            SaveSigninToken = false;
            ValidateActor = false;
            ValidateAudience = true;
            ValidateIssuer = true;
            ValidateIssuerSigningKey = false;
            ValidateLifetime = true;
        }

        //
        // Summary:
        //     Returns a new instance of System.IdentityModel.Tokens.TokenValidationParameters
        //     with values copied from this object.
        //
        // Returns:
        //     A new System.IdentityModel.Tokens.TokenValidationParameters object copied from
        //     this object
        //
        // Remarks:
        //     This is a shallow Clone.
        public virtual TokenValidationParameters Clone()
        {
            return new TokenValidationParameters(this);
        }

        //
        // Summary:
        //     Creates a System.Security.Claims.ClaimsIdentity using:
        //
        //     System.IdentityModel.Tokens.TokenValidationParameters.AuthenticationType
        //
        //     'NameClaimType' is calculated: If NameClaimTypeRetriever call that else use NameClaimType.
        //     If the result is a null or empty string, use System.Security.Claims.ClaimsIdentity.DefaultNameClaimType
        //
        //
        //     .
        //
        //     'RoleClaimType' is calculated: If RoleClaimTypeRetriever call that else use RoleClaimType.
        //     If the result is a null or empty string, use System.Security.Claims.ClaimsIdentity.DefaultRoleClaimType
        //
        //
        //     .
        //
        // Returns:
        //     A System.Security.Claims.ClaimsIdentity with Authentication, NameClaimType and
        //     RoleClaimType set.
        public virtual ClaimsIdentity CreateClaimsIdentity(SecurityToken securityToken, string issuer)
        {
            string text = null;
            text = ((NameClaimTypeRetriever == null) ? NameClaimType : NameClaimTypeRetriever(securityToken, issuer));
            return new ClaimsIdentity(roleType: ((RoleClaimTypeRetriever == null) ? RoleClaimType : RoleClaimTypeRetriever(securityToken, issuer)) ?? "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", authenticationType: AuthenticationType ?? DefaultAuthenticationType, nameType: text ?? "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
        }
    }
}