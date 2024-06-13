//using Microsoft.IdentityModel.Tokens;
//using System;
//using System.Collections.Generic;
//using System.Collections.ObjectModel;
//using System.Globalization;
//using System.IdentityModel.Tokens.Jwt;
//using System.IO;
//using System.Reflection;
//using System.Security.Claims;
//using System.Security.Cryptography.X509Certificates;
//using System.Text;
//using System.Text.RegularExpressions;
//using System.Xml;

//namespace WebNet4_8.App_Start.OidcSecurity
//{
//    public interface ISecurityTokenValidator
//    {
//        //
//        // Summary:
//        //     Gets and sets the maximum size in bytes, that a will be processed.
//        int MaximumTokenSizeInBytes { get; set; }

//        //
//        // Summary:
//        //     Returns true if the token can be read, false otherwise.
//        bool CanReadToken(string securityToken);

//        //
//        // Summary:
//        //     Validates a token passed as a string using System.IdentityModel.Tokens.TokenValidationParameters
//        ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken);
//    }

//    public class SignatureProviderFactory
//    {
//        //
//        // Summary:
//        //     This is the minimum System.IdentityModel.Tokens.AsymmetricSecurityKey.KeySize
//        //     when creating signatures.
//        public static readonly int AbsoluteMinimumAsymmetricKeySizeInBitsForSigning = 2048;

//        //
//        // Summary:
//        //     This is the minimum System.IdentityModel.Tokens.AsymmetricSecurityKey.KeySize
//        //     when verifying signatures.
//        public static readonly int AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying = 1024;

//        //
//        // Summary:
//        //     This is the minimum System.IdentityModel.Tokens.SymmetricSecurityKey.KeySize
//        //     when creating and verifying signatures.
//        public static readonly int AbsoluteMinimumSymmetricKeySizeInBits = 128;

//        private static int minimumAsymmetricKeySizeInBitsForSigning = AbsoluteMinimumAsymmetricKeySizeInBitsForSigning;

//        private static int minimumAsymmetricKeySizeInBitsForVerifying = AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying;

//        private static int minimumSymmetricKeySizeInBits = AbsoluteMinimumSymmetricKeySizeInBits;

//        //
//        // Summary:
//        //     Gets or sets the minimum System.IdentityModel.Tokens.SymmetricSecurityKey.KeySize"/>.
//        //
//        //
//        // Exceptions:
//        //   T:System.ArgumentOutOfRangeException:
//        //     'value' is smaller than System.IdentityModel.Tokens.SignatureProviderFactory.AbsoluteMinimumSymmetricKeySizeInBits.
//        public static int MinimumSymmetricKeySizeInBits
//        {
//            get
//            {
//                return minimumSymmetricKeySizeInBits;
//            }
//            set
//            {
//                if (value < AbsoluteMinimumSymmetricKeySizeInBits)
//                {
//                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, "IDX10628: Cannot set the MinimumSymmetricKeySizeInBits to less than: '{0}'.", new object[1] { AbsoluteMinimumSymmetricKeySizeInBits }));
//                }

//                minimumSymmetricKeySizeInBits = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the minimum System.IdentityModel.Tokens.AsymmetricSecurityKey.KeySize
//        //     for creating signatures.
//        //
//        // Exceptions:
//        //   T:System.ArgumentOutOfRangeException:
//        //     'value' is smaller than System.IdentityModel.Tokens.SignatureProviderFactory.AbsoluteMinimumAsymmetricKeySizeInBitsForSigning.
//        public static int MinimumAsymmetricKeySizeInBitsForSigning
//        {
//            get
//            {
//                return minimumAsymmetricKeySizeInBitsForSigning;
//            }
//            set
//            {
//                if (value < AbsoluteMinimumAsymmetricKeySizeInBitsForSigning)
//                {
//                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, "IDX10613: Cannot set the MinimumAsymmetricKeySizeInBitsForSigning to less than: '{0}'.", new object[1] { AbsoluteMinimumAsymmetricKeySizeInBitsForSigning }));
//                }

//                minimumAsymmetricKeySizeInBitsForSigning = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the minimum System.IdentityModel.Tokens.AsymmetricSecurityKey.KeySize
//        //     for verifying signatures. 'value' is smaller than System.IdentityModel.Tokens.SignatureProviderFactory.AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying.
//        public static int MinimumAsymmetricKeySizeInBitsForVerifying
//        {
//            get
//            {
//                return minimumAsymmetricKeySizeInBitsForVerifying;
//            }
//            set
//            {
//                if (value < AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying)
//                {
//                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, "IDX10627: Cannot set the MinimumAsymmetricKeySizeInBitsForVerifying to less than: '{0}'.", new object[1] { AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying }));
//                }

//                minimumAsymmetricKeySizeInBitsForVerifying = value;
//            }
//        }

//        //
//        // Summary:
//        //     Creates a System.IdentityModel.Tokens.SignatureProvider that supports the System.IdentityModel.Tokens.SecurityKey
//        //     and algorithm.
//        //
//        // Parameters:
//        //   key:
//        //     The System.IdentityModel.Tokens.SecurityKey to use for signing.
//        //
//        //   algorithm:
//        //     The algorithm to use for signing.
//        //
//        // Returns:
//        //     The System.IdentityModel.Tokens.SignatureProvider.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'key' is null.
//        //
//        //   T:System.ArgumentNullException:
//        //     'algorithm' is null.
//        //
//        //   T:System.ArgumentException:
//        //     'algorithm' contains only whitespace.
//        //
//        //   T:System.ArgumentException:
//        //     'System.IdentityModel.Tokens.SecurityKey' is not a System.IdentityModel.Tokens.AsymmetricSecurityKey
//        //     or a System.IdentityModel.Tokens.SymmetricSecurityKey.
//        //
//        //   T:System.ArgumentOutOfRangeException:
//        //     'System.IdentityModel.Tokens.AsymmetricSecurityKey' is smaller than System.IdentityModel.Tokens.SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning.
//        //
//        //
//        //   T:System.ArgumentOutOfRangeException:
//        //     'System.IdentityModel.Tokens.SymmetricSecurityKey' is smaller than System.IdentityModel.Tokens.SignatureProviderFactory.MinimumSymmetricKeySizeInBits.
//        //
//        //
//        // Remarks:
//        //     AsymmetricSignatureProviders require access to a PrivateKey for Signing.
//        public virtual SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
//        {
//            return CreateProvider(key, algorithm, willCreateSignatures: true);
//        }

//        //
//        // Summary:
//        //     Returns a System.IdentityModel.Tokens.SignatureProvider instance supports the
//        //     System.IdentityModel.Tokens.SecurityKey and algorithm.
//        //
//        // Parameters:
//        //   key:
//        //     The System.IdentityModel.Tokens.SecurityKey to use for signing.
//        //
//        //   algorithm:
//        //     The algorithm to use for signing.
//        //
//        // Returns:
//        //     The System.IdentityModel.Tokens.SignatureProvider.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'key' is null.
//        //
//        //   T:System.ArgumentNullException:
//        //     'algorithm' is null.
//        //
//        //   T:System.ArgumentException:
//        //     'algorithm' contains only whitespace.
//        //
//        //   T:System.ArgumentException:
//        //     'System.IdentityModel.Tokens.SecurityKey' is not a System.IdentityModel.Tokens.AsymmetricSecurityKey
//        //     or a System.IdentityModel.Tokens.SymmetricSecurityKey.
//        //
//        //   T:System.ArgumentOutOfRangeException:
//        //     'System.IdentityModel.Tokens.AsymmetricSecurityKey' is smaller than System.IdentityModel.Tokens.SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying.
//        //
//        //
//        //   T:System.ArgumentOutOfRangeException:
//        //     'System.IdentityModel.Tokens.SymmetricSecurityKey' is smaller than System.IdentityModel.Tokens.SignatureProviderFactory.MinimumSymmetricKeySizeInBits.
//        public virtual SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
//        {
//            return CreateProvider(key, algorithm, willCreateSignatures: false);
//        }

//        //
//        // Summary:
//        //     When finished with a System.IdentityModel.Tokens.SignatureProvider call this
//        //     method for cleanup. The default behavior is to call System.IdentityModel.Tokens.SignatureProvider.Dispose(System.Boolean)
//        //
//        //
//        // Parameters:
//        //   signatureProvider:
//        //     System.IdentityModel.Tokens.SignatureProvider to be released.
//        public virtual void ReleaseProvider(SignatureProvider signatureProvider)
//        {
//            signatureProvider?.Dispose();
//        }

//        private static SignatureProvider CreateProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
//        {
//            if (key == null)
//            {
//                throw new ArgumentNullException("key");
//            }

//            if (algorithm == null)
//            {
//                throw new ArgumentNullException("algorithm");
//            }

//            if (string.IsNullOrWhiteSpace(algorithm))
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10002: The parameter '{0}' cannot be 'null' or a string containing only whitespace.", new object[1] { "algorithm " }));
//            }

//            if (key is AsymmetricSecurityKey asymmetricSecurityKey)
//            {
//                if (willCreateSignatures && asymmetricSecurityKey.KeySize < MinimumAsymmetricKeySizeInBitsForSigning)
//                {
//                    throw new ArgumentOutOfRangeException("key.KeySize", asymmetricSecurityKey.KeySize, string.Format(CultureInfo.InvariantCulture, "IDX10630: The '{0}' for signing cannot be smaller than '{1}' bits.", new object[2]
//                    {
//                    key.GetType(),
//                    MinimumAsymmetricKeySizeInBitsForSigning
//                    }));
//                }

//                if (asymmetricSecurityKey.KeySize < MinimumAsymmetricKeySizeInBitsForVerifying)
//                {
//                    throw new ArgumentOutOfRangeException("key.KeySize", asymmetricSecurityKey.KeySize, string.Format(CultureInfo.InvariantCulture, "IDX10631: The '{0}' for verifying cannot be smaller than '{1}' bits.", new object[2]
//                    {
//                    key.GetType(),
//                    MinimumAsymmetricKeySizeInBitsForVerifying
//                    }));
//                }

//                return new AsymmetricSignatureProvider(asymmetricSecurityKey, algorithm, willCreateSignatures);
//            }

//            if (key is SymmetricSecurityKey symmetricSecurityKey)
//            {
//                if (symmetricSecurityKey.KeySize < MinimumSymmetricKeySizeInBits)
//                {
//                    throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, "IDX10603: The '{0}' cannot have less than: '{1}' bits.", new object[2]
//                    {
//                    key.GetType(),
//                    MinimumSymmetricKeySizeInBits
//                    }));
//                }

//                return new SymmetricSignatureProvider(symmetricSecurityKey, algorithm);
//            }

//            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10600: '{0}' supports: '{1}' of types: '{2}' or '{3}'. SecurityKey received was of type: '{4}'.", typeof(SignatureProvider).ToString(), typeof(SecurityKey), typeof(AsymmetricSecurityKey), typeof(SymmetricSecurityKey), key.GetType()));
//        }
//    }

//    public class JwtSecurityTokenHandler : System.IdentityModel.Tokens.SecurityTokenHandler, ISecurityTokenValidator
//    {
//        private delegate bool CertMatcher(X509Certificate2 cert);

//        private static IDictionary<string, string> outboundAlgorithmMap;

//        private static IDictionary<string, string> inboundAlgorithmMap;

//        private static IDictionary<string, string> inboundClaimTypeMap;

//        private static IDictionary<string, string> outboundClaimTypeMap;

//        private static string shortClaimTypeProperty;

//        private static string jsonClaimTypeProperty;

//        private static ISet<string> inboundClaimFilter;

//        private static string[] tokenTypeIdentifiers;

//        private SignatureProviderFactory signatureProviderFactory = new SignatureProviderFactory();

//        private int _maximumTokenSizeInBytes = 2097152;

//        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;

//        //
//        // Summary:
//        //     Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore'
//        //     are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore
//        //     = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
//        public static readonly int DefaultTokenLifetimeInMinutes;

//        private static FieldInfo _certFieldInfo;

//        private static Type _x509AsymmKeyType;

//        //
//        // Summary:
//        //     Gets or sets the System.Collections.Generic.IDictionary`2 used to map Inbound
//        //     Cryptographic Algorithms.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'value' is null.
//        //
//        // Remarks:
//        //     Strings that describe Cryptographic Algorithms that are understood by the runtime
//        //     are not necessarily the same values used in the JsonWebToken specification.
//        //
//        //     When a System.IdentityModel.Tokens.JwtSecurityToken signature is validated, the
//        //     algorithm is obtained from the HeaderParameter { alg, 'value' }. The 'value'
//        //     is translated according to this mapping and the translated 'value' is used when
//        //     performing cryptographic operations.
//        //
//        //     Default mapping is:
//        //
//        //     RS256 => http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
//        //
//        //     HS256 => http://www.w3.org/2001/04/xmldsig-more#hmac-sha256
//        public static IDictionary<string, string> InboundAlgorithmMap
//        {
//            get
//            {
//                return inboundAlgorithmMap;
//            }
//            set
//            {
//                if (value == null)
//                {
//                    throw new ArgumentNullException("value");
//                }

//                inboundAlgorithmMap = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the System.Collections.Generic.IDictionary`2 used to map Outbound
//        //     Cryptographic Algorithms.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'value' is null.
//        //
//        // Remarks:
//        //     Strings that describe Cryptographic Algorithms understood by the runtime are
//        //     not necessarily the same in the JsonWebToken specification.
//        //
//        //     This property contains mappings the will be used to when creating a System.IdentityModel.Tokens.JwtHeader
//        //     and setting the HeaderParameter { alg, 'value' }. The 'value' set is translated
//        //     according to this mapping.
//        //
//        //     Default mapping is:
//        //
//        //     http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 => RS256
//        //
//        //     http://www.w3.org/2001/04/xmldsig-more#hmac-sha256 => HS256
//        public static IDictionary<string, string> OutboundAlgorithmMap
//        {
//            get
//            {
//                return outboundAlgorithmMap;
//            }
//            set
//            {
//                if (value == null)
//                {
//                    throw new ArgumentNullException("value");
//                }

//                outboundAlgorithmMap = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the System.IdentityModel.Tokens.JwtSecurityTokenHandler.InboundClaimTypeMap
//        //     that is used when setting the System.Security.Claims.Claim.Type for claims in
//        //     the System.Security.Claims.ClaimsPrincipal extracted when validating a System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        //
//        //     The System.Security.Claims.Claim.Type is set to the JSON claim 'name' after translating
//        //     using this mapping.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'value is null.
//        public static IDictionary<string, string> InboundClaimTypeMap
//        {
//            get
//            {
//                return inboundClaimTypeMap;
//            }
//            set
//            {
//                if (value == null)
//                {
//                    throw new ArgumentNullException("value");
//                }

//                inboundClaimTypeMap = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the System.IdentityModel.Tokens.JwtSecurityTokenHandler.OutboundClaimTypeMap
//        //     that is used when creating a System.IdentityModel.Tokens.JwtSecurityToken from
//        //     System.Security.Claims.Claim(s).
//        //
//        //     The JSON claim 'name' value is set to System.Security.Claims.Claim.Type after
//        //     translating using this mapping.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'value is null.
//        //
//        // Remarks:
//        //     This mapping is applied only when using System.IdentityModel.Tokens.JwtPayload.AddClaim(System.Security.Claims.Claim)
//        //     or System.IdentityModel.Tokens.JwtPayload.AddClaims(System.Collections.Generic.IEnumerable{System.Security.Claims.Claim}).
//        //     Adding values directly will not result in translation.
//        public static IDictionary<string, string> OutboundClaimTypeMap
//        {
//            get
//            {
//                return outboundClaimTypeMap;
//            }
//            set
//            {
//                if (value == null)
//                {
//                    throw new ArgumentNullException("value");
//                }

//                outboundClaimTypeMap = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the System.Collections.Generic.ISet`1 used to filter claims when
//        //     populating a System.Security.Claims.ClaimsIdentity claims form a System.IdentityModel.Tokens.JwtSecurityToken.
//        //     When a System.IdentityModel.Tokens.JwtSecurityToken is validated, claims with
//        //     types found in this System.Collections.Generic.ISet`1 will not be added to the
//        //     System.Security.Claims.ClaimsIdentity.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'value' is null.
//        public static ISet<string> InboundClaimFilter
//        {
//            get
//            {
//                return inboundClaimFilter;
//            }
//            set
//            {
//                if (value == null)
//                {
//                    throw new ArgumentNullException("value");
//                }

//                inboundClaimFilter = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the property name of System.Security.Claims.Claim.Properties the
//        //     will contain the original JSON claim 'name' if a mapping occurred when the System.Security.Claims.Claim(s)
//        //     were created.
//        //
//        //     See System.IdentityModel.Tokens.JwtSecurityTokenHandler.InboundClaimTypeMap for
//        //     more information.
//        //
//        // Exceptions:
//        //   T:System.ArgumentException:
//        //     if System.String.IsIsNullOrWhiteSpace('value') is true.
//        public static string ShortClaimTypeProperty
//        {
//            get
//            {
//                return shortClaimTypeProperty;
//            }
//            set
//            {
//                if (string.IsNullOrWhiteSpace(value))
//                {
//                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10000: The parameter '{0}' cannot be a 'null' or an empty string.", new object[1] { "value" }));
//                }

//                shortClaimTypeProperty = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the property name of System.Security.Claims.Claim.Properties the
//        //     will contain .Net type that was recogninzed when JwtPayload.Claims serialized
//        //     the value to JSON.
//        //
//        //     See System.IdentityModel.Tokens.JwtSecurityTokenHandler.InboundClaimTypeMap for
//        //     more information.
//        //
//        // Exceptions:
//        //   T:System.ArgumentException:
//        //     if System.String.IsIsNullOrWhiteSpace('value') is true.
//        public static string JsonClaimTypeProperty
//        {
//            get
//            {
//                return jsonClaimTypeProperty;
//            }
//            set
//            {
//                if (string.IsNullOrWhiteSpace(value))
//                {
//                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10000: The parameter '{0}' cannot be a 'null' or an empty string.", new object[1] { "value" }));
//                }

//                jsonClaimTypeProperty = value;
//            }
//        }

//        //
//        // Summary:
//        //     Returns 'true' which indicates this instance can validate a System.IdentityModel.Tokens.JwtSecurityToken.
//        public override bool CanValidateToken => true;

//        //
//        // Summary:
//        //     Returns 'true', which indicates this instance can write System.IdentityModel.Tokens.JwtSecurityToken.
//        public override bool CanWriteToken => true;

//        //
//        // Summary:
//        //     Gets and sets the token lifetime in minutes.
//        //
//        // Exceptions:
//        //   T:System.ArgumentOutOfRangeException:
//        //     'value' less than 1.
//        public int TokenLifetimeInMinutes
//        {
//            get
//            {
//                return _defaultTokenLifetimeInMinutes;
//            }
//            set
//            {
//                if (value < 1)
//                {
//                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, "IDX10104: TokenLifetimeInMinutes must be greater than zero. value: '{0}'", new object[1] { value.ToString(CultureInfo.InvariantCulture) }));
//                }

//                _defaultTokenLifetimeInMinutes = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets and sets the maximum size in bytes, that a will be processed.
//        //
//        // Exceptions:
//        //   T:System.ArgumentOutOfRangeException:
//        //     'value' less than 1.
//        public int MaximumTokenSizeInBytes
//        {
//            get
//            {
//                return _maximumTokenSizeInBytes;
//            }
//            set
//            {
//                if (value < 1)
//                {
//                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, "IDX10101: MaximumTokenSizeInBytes must be greater than zero. value: '{0}'", new object[1] { value.ToString(CultureInfo.InvariantCulture) }));
//                }

//                _maximumTokenSizeInBytes = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets or sets the System.IdentityModel.Tokens.JwtSecurityTokenHandler.SignatureProviderFactory
//        //     for creating System.IdentityModel.Tokens.SignatureProvider(s).
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'value' is null.
//        //
//        // Remarks:
//        //     This extensibility point can be used to insert custom System.IdentityModel.Tokens.SignatureProvider(s).
//        //
//        //
//        //     System.IdentityModel.Tokens.SignatureProviderFactory.CreateForVerifying(System.IdentityModel.Tokens.SecurityKey,System.String)
//        //     is called to obtain a System.IdentityModel.Tokens.SignatureProvider(s) when needed.
//        public SignatureProviderFactory SignatureProviderFactory
//        {
//            get
//            {
//                return signatureProviderFactory;
//            }
//            set
//            {
//                if (value == null)
//                {
//                    throw new ArgumentNullException("value");
//                }

//                signatureProviderFactory = value;
//            }
//        }

//        //
//        // Summary:
//        //     Gets the System.Type supported by this handler.
//        public override Type TokenType => typeof(JwtSecurityToken);

//        static JwtSecurityTokenHandler()
//        {
//            outboundAlgorithmMap = new Dictionary<string, string>
//        {
//            { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RS256" },
//            { "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HS256" }
//        };
//            inboundAlgorithmMap = new Dictionary<string, string>
//        {
//            { "RS256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" },
//            { "HS256", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256" }
//        };
//            inboundClaimTypeMap = ClaimTypeMapping.InboundClaimTypeMap;
//            outboundClaimTypeMap = ClaimTypeMapping.OutboundClaimTypeMap;
//            shortClaimTypeProperty = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName";
//            jsonClaimTypeProperty = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/json_type";
//            inboundClaimFilter = ClaimTypeMapping.InboundClaimFilter;
//            tokenTypeIdentifiers = new string[2] { "urn:ietf:params:oauth:token-type:jwt", "JWT" };
//            DefaultTokenLifetimeInMinutes = 60;
//            _x509AsymmKeyType = typeof(X509AsymmetricSecurityKey);
//            _certFieldInfo = _x509AsymmKeyType.GetField("certificate", BindingFlags.Instance | BindingFlags.NonPublic);
//        }

//        //
//        // Summary:
//        //     Initializes a new instance of the System.IdentityModel.Tokens.JwtSecurityTokenHandler
//        //     class.
//        public JwtSecurityTokenHandler()
//        {
//        }

//        //
//        // Summary:
//        //     Obsolete method, use System.IdentityModel.Tokens.TokenValidationParameters when
//        //     processing tokens.
//        //
//        // Exceptions:
//        //   T:System.NotSupportedException:
//        //     use System.IdentityModel.Tokens.TokenValidationParameters. when processing tokens.
//        public override void LoadCustomConfiguration(XmlNodeList nodelist)
//        {
//            throw new NotSupportedException("IDX11004: Loading from Configuration is not supported use TokenValidationParameters to set validation parameters.");
//        }

//        //
//        // Summary:
//        //     Determines if the System.Xml.XmlReader is positioned on a well formed <BinarySecurityToken>
//        //     element.
//        //
//        // Parameters:
//        //   reader:
//        //     System.Xml.XmlReader positioned at xml.
//        //
//        // Returns:
//        //     'true' if the reader is positioned at an element <BinarySecurityToken>. in the
//        //     namespace: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
//        //
//        //
//        //     With an attribute of 'valueType' equal to one of:
//        //
//        //     "urn:ietf:params:oauth:token-type:jwt", "JWT"
//        //
//        //     For example: <wsse:BinarySecurityToken valueType = "JWT"> ...
//        //
//        //     'false' otherwise.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'reader' is null.
//        //
//        // Remarks:
//        //     The 'EncodingType' attribute is optional, if it is set, it must be equal to:
//        //     "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary".
//        public override bool CanReadToken(XmlReader reader)
//        {
//            if (reader == null)
//            {
//                throw new ArgumentNullException("reader");
//            }

//            try
//            {
//                reader.MoveToContent();
//                if (reader.IsStartElement("BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"))
//                {
//                    string attribute = reader.GetAttribute("ValueType", null);
//                    string attribute2 = reader.GetAttribute("EncodingType", null);
//                    if (attribute2 != null && !StringComparer.Ordinal.Equals(attribute2, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"))
//                    {
//                        return false;
//                    }

//                    if (attribute != null && !StringComparer.Ordinal.Equals(attribute, "urn:ietf:params:oauth:token-type:jwt") && !StringComparer.OrdinalIgnoreCase.Equals(attribute, "JWT"))
//                    {
//                        return false;
//                    }

//                    return true;
//                }
//            }
//            catch (XmlException)
//            {
//            }
//            catch (InvalidOperationException)
//            {
//            }

//            return false;
//        }

//        //
//        // Summary:
//        //     Determines if the string is a well formed Json Web token (see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-07)
//        //
//        //
//        // Parameters:
//        //   tokenString:
//        //     string that should represent a valid JSON Web Token.
//        //
//        // Returns:
//        //     'true' if the token is in JSON compact serialization format.
//        //
//        //     'false' if token.Length * 2 > System.IdentityModel.Tokens.JwtSecurityTokenHandler.MaximumTokenSizeInBytes.
//        //
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'tokenString' is null.
//        //
//        // Remarks:
//        //     Uses System.Text.RegularExpressions.Regex.IsMatch(System.String,System.String)(
//        //     token, @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$" ).
//        public override bool CanReadToken(string tokenString)
//        {
//            if (tokenString == null)
//            {
//                throw new ArgumentNullException("tokenString");
//            }

//            if (tokenString.Length * 2 > MaximumTokenSizeInBytes)
//            {
//                return false;
//            }

//            if (!Regex.IsMatch(tokenString, "^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*$"))
//            {
//                return CanReadToken(XmlReader.Create(new MemoryStream(Encoding.UTF8.GetBytes(tokenString))));
//            }

//            return true;
//        }

//        //
//        // Summary:
//        //     Creating System.IdentityModel.Tokens.SecurityKeyIdentifierClause is not NotSupported.
//        //
//        //
//        // Exceptions:
//        //   T:System.NotSupportedException:
//        //     to create a System.IdentityModel.Tokens.SecurityKeyIdentifierClause.
//        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
//        {
//            throw new NotSupportedException("IDX11005: Creating a SecurityKeyIdentifierClause is not supported.");
//        }

//        //
//        // Summary:
//        //     Creates a System.IdentityModel.Tokens.JwtSecurityToken based on values found
//        //     in the System.IdentityModel.Tokens.SecurityTokenDescriptor.
//        //
//        // Parameters:
//        //   tokenDescriptor:
//        //     Contains the parameters used to create the token.
//        //
//        // Returns:
//        //     A System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'tokenDescriptor' is null.
//        //
//        // Remarks:
//        //     If System.IdentityModel.Tokens.SecurityTokenDescriptor.SigningCredentials is
//        //     not null, System.IdentityModel.Tokens.JwtSecurityToken.RawData will be signed.
//        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
//        {
//            if (tokenDescriptor == null)
//            {
//                throw new ArgumentNullException("tokenDescriptor");
//            }

//            DateTime? notBefore = ((tokenDescriptor.Lifetime == null) ? null : tokenDescriptor.Lifetime.Created);
//            DateTime? expires = ((tokenDescriptor.Lifetime == null) ? null : tokenDescriptor.Lifetime.Expires);
//            return CreateToken(tokenDescriptor.TokenIssuerName, tokenDescriptor.AppliesToAddress, tokenDescriptor.Subject, notBefore, expires, tokenDescriptor.SigningCredentials);
//        }

//        //
//        // Summary:
//        //     Uses the System.IdentityModel.Tokens.JwtSecurityToken.#ctor(System.IdentityModel.Tokens.JwtHeader,System.IdentityModel.Tokens.JwtPayload,System.String,System.String,System.String)
//        //     constructor, first creating the System.IdentityModel.Tokens.JwtHeader and System.IdentityModel.Tokens.JwtPayload.
//        //
//        //
//        //     If System.IdentityModel.Tokens.SigningCredentials is not null, System.IdentityModel.Tokens.JwtSecurityToken.RawData
//        //     will be signed.
//        //
//        // Parameters:
//        //   issuer:
//        //     the issuer of the token.
//        //
//        //   audience:
//        //     the audience for this token.
//        //
//        //   subject:
//        //     the source of the System.Security.Claims.Claim(s) for this token.
//        //
//        //   notBefore:
//        //     the notbefore time for this token.
//        //
//        //   expires:
//        //     the expiration time for this token.
//        //
//        //   signingCredentials:
//        //     contains cryptographic material for generating a signature.
//        //
//        //   signatureProvider:
//        //     optional System.IdentityModel.Tokens.SignatureProvider.
//        //
//        // Returns:
//        //     A System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        // Exceptions:
//        //   T:System.ArgumentException:
//        //     if 'expires' <= 'notBefore'.
//        //
//        // Remarks:
//        //     If System.Security.Claims.ClaimsIdentity.Actor is not null, then a claim { actort,
//        //     'value' } will be added to the payload. System.IdentityModel.Tokens.JwtSecurityTokenHandler.CreateActorValue(System.Security.Claims.ClaimsIdentity)
//        //     for details on how the value is created.
//        //
//        //     See System.IdentityModel.Tokens.JwtHeader for details on how the HeaderParameters
//        //     are added to the header.
//        //
//        //     See System.IdentityModel.Tokens.JwtPayload for details on how the values are
//        //     added to the payload.
//        public virtual JwtSecurityToken CreateToken(string issuer = null, string audience = null, ClaimsIdentity subject = null, DateTime? notBefore = null, DateTime? expires = null, SigningCredentials signingCredentials = null, SignatureProvider signatureProvider = null)
//        {
//            if (expires.HasValue && notBefore.HasValue && notBefore >= expires)
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10401: Expires: '{0}' must be after NotBefore: '{1}'.", new object[2] { expires.Value, notBefore.Value }));
//            }

//            if (!expires.HasValue && !notBefore.HasValue)
//            {
//                DateTime utcNow = DateTime.UtcNow;
//                expires = utcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes);
//                notBefore = utcNow;
//            }

//            JwtPayload jwtPayload = new JwtPayload(issuer, audience, subject?.Claims, notBefore, expires);
//            JwtHeader jwtHeader = new JwtHeader(signingCredentials);
//            if (subject != null && subject.Actor != null)
//            {
//                jwtPayload.AddClaim(new Claim("actort", CreateActorValue(subject.Actor)));
//            }

//            string text = jwtHeader.Base64UrlEncode();
//            string text2 = jwtPayload.Base64UrlEncode();
//            string rawSignature = string.Empty;
//            string inputString = text + "." + text2;
//            if (signatureProvider != null)
//            {
//                rawSignature = Base64UrlEncoder.Encode(CreateSignature(inputString, null, null, signatureProvider));
//            }
//            else if (signingCredentials != null)
//            {
//                rawSignature = Base64UrlEncoder.Encode(CreateSignature(inputString, signingCredentials.SigningKey, signingCredentials.SignatureAlgorithm, signatureProvider));
//            }

//            return new JwtSecurityToken(jwtHeader, jwtPayload, text, text2, rawSignature);
//        }

//        //
//        // Summary:
//        //     Gets the token type identifier(s) supported by this handler.
//        //
//        // Returns:
//        //     A collection of strings that identify the tokens this instance can handle.
//        //
//        // Remarks:
//        //     When receiving a System.IdentityModel.Tokens.JwtSecurityToken wrapped inside
//        //     a <wsse:BinarySecurityToken> element. The <wsse:BinarySecurityToken> element
//        //     must have the ValueType attribute set to one of these values in order for this
//        //     handler to recognize that it can read the token.
//        public override string[] GetTokenTypeIdentifiers()
//        {
//            return tokenTypeIdentifiers;
//        }

//        //
//        // Summary:
//        //     Reads a JSON web token wrapped inside a WS-Security BinarySecurityToken xml element.
//        //
//        //
//        // Parameters:
//        //   reader:
//        //     The System.Xml.XmlReader pointing at the jwt.
//        //
//        // Returns:
//        //     An instance of System.IdentityModel.Tokens.JwtSecurityToken
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'reader' is null.
//        //
//        //   T:System.ArgumentException:
//        //     if System.IdentityModel.Tokens.JwtSecurityTokenHandler.CanReadToken(System.Xml.XmlReader)
//        //     returns false.
//        //
//        // Remarks:
//        //     First calls System.IdentityModel.Tokens.JwtSecurityToken.CanReadToken
//        //
//        //     The reader must be positioned at an element named:
//        //
//        //     BinarySecurityToken'. in the namespace: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
//        //     with a 'ValueType' attribute equal to one of: "urn:ietf:params:oauth:token-type:jwt",
//        //     "JWT".
//        //
//        //     For example <wsse:BinarySecurityToken valueType = "JWT"> ...
//        //
//        //     The 'EncodingType' attribute is optional, if it is set, it must be equal to:
//        //     "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
//        public override SecurityToken ReadToken(XmlReader reader)
//        {
//            if (reader == null)
//            {
//                throw new ArgumentNullException("reader");
//            }

//            if (!CanReadToken(reader))
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10707: '{0}' cannot read this xml: '{1}'. The reader needs to be positioned at an element: '{2}', within the namespace: '{3}', with an attribute: '{4}' equal to one of the following: '{5}', '{6}'.", GetType().ToString(), reader.ReadOuterXml(), "BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "ValueType", "urn:ietf:params:oauth:token-type:jwt", "JWT"));
//            }

//            using XmlDictionaryReader xmlDictionaryReader = XmlDictionaryReader.CreateDictionaryReader(reader);
//            string attribute = xmlDictionaryReader.GetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
//            JwtSecurityToken jwtSecurityToken = ReadToken(Encoding.UTF8.GetString(xmlDictionaryReader.ReadElementContentAsBase64())) as JwtSecurityToken;
//            if (attribute != null)
//            {
//                jwtSecurityToken?.SetId(attribute);
//            }

//            return jwtSecurityToken;
//        }

//        //
//        // Summary:
//        //     Reads a token encoded in JSON Compact serialized format.
//        //
//        // Parameters:
//        //   tokenString:
//        //     A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed
//        //     using 'JSON Web Signature' (JWS).
//        //
//        // Returns:
//        //     A System.IdentityModel.Tokens.JwtSecurityToken
//        //
//        // Remarks:
//        //     The JWT must be encoded using Base64Url encoding of the UTF-8 representation
//        //     of the JWT: Header, Payload and Signature. The contents of the JWT returned are
//        //     not validated in any way, the token is simply decoded. Use ValidateToken to validate
//        //     the JWT.
//        public override SecurityToken ReadToken(string tokenString)
//        {
//            if (tokenString == null)
//            {
//                throw new ArgumentNullException("token");
//            }

//            if (tokenString.Length * 2 > MaximumTokenSizeInBytes)
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10209: token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.", new object[2] { tokenString.Length, MaximumTokenSizeInBytes }));
//            }

//            if (!CanReadToken(tokenString))
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10708: '{0}' cannot read this string: '{1}'.\nThe string needs to be in compact JSON format, which is of the form: '<Base64UrlEncodedHeader>.<Base64UrlEndcodedPayload>.<OPTIONAL, Base64UrlEncodedSignature>'.", new object[2]
//                {
//                GetType(),
//                tokenString
//                }));
//            }

//            if (Regex.IsMatch(tokenString, "^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*$"))
//            {
//                return new JwtSecurityToken(tokenString);
//            }

//            return ReadToken(XmlReader.Create(new MemoryStream(Encoding.UTF8.GetBytes(tokenString))));
//        }

//        //
//        // Summary:
//        //     Obsolete method, use System.IdentityModel.Tokens.JwtSecurityTokenHandler.ValidateToken(System.String,System.IdentityModel.Tokens.TokenValidationParameters,System.IdentityModel.Tokens.SecurityToken@).
//        //
//        //
//        // Exceptions:
//        //   T:System.NotSupportedException:
//        //     use System.IdentityModel.Tokens.JwtSecurityTokenHandler.ValidateToken(System.String,System.IdentityModel.Tokens.TokenValidationParameters,System.IdentityModel.Tokens.SecurityToken@).
//        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
//        {
//            throw new NotSupportedException("IDX11008: This method is not supported to validate a 'jwt' use the method: ValidateToken(String, TokenValidationParameters, out SecurityToken).");
//        }

//        //
//        // Summary:
//        //     Reads and validates a token encoded in JSON Compact serialized format.
//        //
//        // Parameters:
//        //   securityToken:
//        //     A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed
//        //     using 'JSON Web Signature' (JWS).
//        //
//        //   validationParameters:
//        //     Contains validation parameters for the System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        //
//        //   validatedToken:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken that was validated.
//        //
//        // Returns:
//        //     A System.Security.Claims.ClaimsPrincipal from the jwt. Does not include the header
//        //     claims.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'securityToken' is null or whitespace.
//        //
//        //   T:System.ArgumentNullException:
//        //     'validationParameters' is null.
//        //
//        //   T:System.ArgumentException:
//        //     'securityToken.Length' > System.IdentityModel.Tokens.JwtSecurityTokenHandler.MaximumTokenSizeInBytes.
//        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
//        {
//            if (string.IsNullOrWhiteSpace(securityToken))
//            {
//                throw new ArgumentNullException("securityToken");
//            }

//            if (validationParameters == null)
//            {
//                throw new ArgumentNullException("validationParameters");
//            }

//            if (securityToken.Length > MaximumTokenSizeInBytes)
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10209: token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.", new object[2] { securityToken.Length, MaximumTokenSizeInBytes }));
//            }

//            JwtSecurityToken jwtSecurityToken = ValidateSignature(securityToken, validationParameters);
//            if (jwtSecurityToken.SigningKey != null)
//            {
//                ValidateIssuerSecurityKey(jwtSecurityToken.SigningKey, jwtSecurityToken, validationParameters);
//            }

//            DateTime? notBefore = null;
//            if (jwtSecurityToken.Payload.Nbf.HasValue)
//            {
//                notBefore = jwtSecurityToken.ValidFrom;
//            }

//            DateTime? dateTime = null;
//            if (jwtSecurityToken.Payload.Exp.HasValue)
//            {
//                dateTime = jwtSecurityToken.ValidTo;
//            }

//            Validators.ValidateTokenReplay(securityToken, dateTime, validationParameters);
//            if (validationParameters.ValidateLifetime)
//            {
//                if (validationParameters.LifetimeValidator != null)
//                {
//                    if (!validationParameters.LifetimeValidator(notBefore, dateTime, jwtSecurityToken, validationParameters))
//                    {
//                        throw new SecurityTokenInvalidLifetimeException(string.Format(CultureInfo.InvariantCulture, "IDX10230: Lifetime validation failed. Delegate returned false, securitytoken: '{0}'.", new object[1] { jwtSecurityToken.ToString() }));
//                    }
//                }
//                else
//                {
//                    ValidateLifetime(notBefore, dateTime, jwtSecurityToken, validationParameters);
//                }
//            }

//            if (validationParameters.ValidateAudience)
//            {
//                if (validationParameters.AudienceValidator != null)
//                {
//                    if (!validationParameters.AudienceValidator(jwtSecurityToken.Audiences, jwtSecurityToken, validationParameters))
//                    {
//                        throw new SecurityTokenInvalidAudienceException(string.Format(CultureInfo.InvariantCulture, "IDX10231: Audience validation failed. Delegate returned false, securitytoken: '{0}'.", new object[1] { jwtSecurityToken.ToString() }));
//                    }
//                }
//                else
//                {
//                    ValidateAudience(jwtSecurityToken.Audiences, jwtSecurityToken, validationParameters);
//                }
//            }

//            string issuer = jwtSecurityToken.Issuer;
//            if (validationParameters.ValidateIssuer)
//            {
//                issuer = ((validationParameters.IssuerValidator == null) ? ValidateIssuer(issuer, jwtSecurityToken, validationParameters) : validationParameters.IssuerValidator(issuer, jwtSecurityToken, validationParameters));
//            }

//            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwtSecurityToken.Actor))
//            {
//                SecurityToken validatedToken2 = null;
//                ValidateToken(jwtSecurityToken.Actor, validationParameters, out validatedToken2);
//            }

//            ClaimsIdentity claimsIdentity = CreateClaimsIdentity(jwtSecurityToken, issuer, validationParameters);
//            if (validationParameters.SaveSigninToken)
//            {
//                claimsIdentity.BootstrapContext = new BootstrapContext(securityToken);
//            }

//            validatedToken = jwtSecurityToken;
//            return new ClaimsPrincipal(claimsIdentity);
//        }

//        //
//        // Summary:
//        //     Writes the System.IdentityModel.Tokens.JwtSecurityToken wrapped in a WS-Security
//        //     BinarySecurityToken using the System.Xml.XmlWriter.
//        //
//        // Parameters:
//        //   writer:
//        //     System.Xml.XmlWriter used to write token.
//        //
//        //   token:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken that will be written.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'writer' is null.
//        //
//        //   T:System.ArgumentNullException:
//        //     'token' is null.
//        //
//        //   T:System.ArgumentException:
//        //     'token' is not a not System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        // Remarks:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken current contents are encoded.
//        //     If System.IdentityModel.Tokens.JwtSecurityToken.SigningCredentials is not null,
//        //     the encoding will contain a signature.
//        public override void WriteToken(XmlWriter writer, SecurityToken token)
//        {
//            if (writer == null)
//            {
//                throw new ArgumentNullException("writer");
//            }

//            if (token == null)
//            {
//                throw new ArgumentNullException("token");
//            }

//            if (!(token is JwtSecurityToken))
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10226: '{0}' can only write SecurityTokens of type: '{1}', 'token' type is: '{2}'.", new object[3]
//                {
//                GetType(),
//                typeof(JwtSecurityToken),
//                token.GetType()
//                }));
//            }

//            byte[] bytes = Encoding.UTF8.GetBytes(WriteToken(token));
//            writer.WriteStartElement("wsse", "BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
//            if (token.Id != null)
//            {
//                writer.WriteAttributeString("wsse", "Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", token.Id);
//            }

//            writer.WriteAttributeString("ValueType", null, "urn:ietf:params:oauth:token-type:jwt");
//            writer.WriteAttributeString("EncodingType", null, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
//            writer.WriteBase64(bytes, 0, bytes.Length);
//            writer.WriteEndElement();
//        }

//        //
//        // Summary:
//        //     Writes the System.IdentityModel.Tokens.JwtSecurityToken as a JSON Compact serialized
//        //     format string.
//        //
//        // Parameters:
//        //   token:
//        //     System.IdentityModel.Tokens.JwtSecurityToken to serialize.
//        //
//        // Returns:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken as a signed (if System.IdentityModel.Tokens.SigningCredentials
//        //     exist) encoded string.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'token' is null.
//        //
//        //   T:System.ArgumentException:
//        //     'token' is not a not System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        // Remarks:
//        //     If the System.IdentityModel.Tokens.JwtSecurityToken.SigningCredentials are not
//        //     null, the encoding will contain a signature.
//        public override string WriteToken(SecurityToken token)
//        {
//            if (token == null)
//            {
//                throw new ArgumentNullException("token");
//            }

//            if (!(token is JwtSecurityToken jwtSecurityToken))
//            {
//                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "IDX10706: '{0}' can only write SecurityTokens of type: '{1}', 'token' type is: '{2}'.", new object[3]
//                {
//                GetType(),
//                typeof(JwtSecurityToken),
//                token.GetType()
//                }));
//            }

//            string text = string.Empty;
//            string text2 = jwtSecurityToken.EncodedHeader + "." + jwtSecurityToken.EncodedPayload;
//            if (jwtSecurityToken.SigningCredentials != null)
//            {
//                text = Base64UrlEncoder.Encode(CreateSignature(text2, jwtSecurityToken.SigningCredentials.SigningKey, jwtSecurityToken.SigningCredentials.SignatureAlgorithm));
//            }

//            return text2 + "." + text;
//        }

//        //
//        // Summary:
//        //     Produces a signature over the 'input' using the System.IdentityModel.Tokens.SecurityKey
//        //     and algorithm specified.
//        //
//        // Parameters:
//        //   inputString:
//        //     string to be signed
//        //
//        //   key:
//        //     the System.IdentityModel.Tokens.SecurityKey to use.
//        //
//        //   algorithm:
//        //     the algorithm to use.
//        //
//        //   signatureProvider:
//        //     if provided, the System.IdentityModel.Tokens.SignatureProvider will be used to
//        //     sign the token
//        //
//        // Returns:
//        //     The signature over the bytes obtained from UTF8Encoding.GetBytes( 'input' ).
//        //
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'input' is null.
//        //
//        //   T:System.InvalidProgramException:
//        //     System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning(System.IdentityModel.Tokens.SecurityKey,System.String)
//        //     returns null.
//        //
//        // Remarks:
//        //     The System.IdentityModel.Tokens.SignatureProvider used to created the signature
//        //     is obtained by calling System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning(System.IdentityModel.Tokens.SecurityKey,System.String).
//        internal byte[] CreateSignature(string inputString, SecurityKey key, string algorithm, SignatureProvider signatureProvider = null)
//        {
//            if (inputString == null)
//            {
//                throw new ArgumentNullException("inputString");
//            }

//            if (signatureProvider != null)
//            {
//                return signatureProvider.Sign(Encoding.UTF8.GetBytes(inputString));
//            }

//            SignatureProvider signatureProvider2 = SignatureProviderFactory.CreateForSigning(key, algorithm);
//            if (signatureProvider2 == null)
//            {
//                throw new InvalidProgramException(string.Format(CultureInfo.InvariantCulture, "IDX10635: Unable to create signature. '{0}' returned a null '{1}'. SecurityKey: '{2}', Algorithm: '{3}'", SignatureProviderFactory.GetType(), typeof(SignatureProvider), (key == null) ? "<null>" : key.GetType().ToString(), (algorithm == null) ? "<null>" : algorithm));
//            }

//            byte[] result = signatureProvider2.Sign(Encoding.UTF8.GetBytes(inputString));
//            SignatureProviderFactory.ReleaseProvider(signatureProvider2);
//            return result;
//        }

//        private bool ValidateSignature(byte[] encodedBytes, byte[] signature, SecurityKey key, string algorithm)
//        {
//            SignatureProvider signatureProvider = SignatureProviderFactory.CreateForVerifying(key, algorithm);
//            if (signatureProvider == null)
//            {
//                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "IDX10636: SignatureProviderFactory.CreateForVerifying returned null for key: '{0}', signatureAlgorithm: '{1}'.", new object[2]
//                {
//                (key == null) ? "null" : key.ToString(),
//                (algorithm == null) ? "null" : algorithm
//                }));
//            }

//            return signatureProvider.Verify(encodedBytes, signature);
//        }

//        //
//        // Summary:
//        //     Validates that the signature, if found and / or required is valid.
//        //
//        // Parameters:
//        //   token:
//        //     A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed
//        //     using 'JSON Web Signature' (JWS).
//        //
//        //   validationParameters:
//        //     System.IdentityModel.Tokens.TokenValidationParameters that contains signing keys.
//        //
//        //
//        // Returns:
//        //     System.IdentityModel.Tokens.JwtSecurityToken that has the signature validated
//        //     if token was signed and System.IdentityModel.Tokens.TokenValidationParameters.RequireSignedTokens
//        //     is true.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     thrown if 'token is null or whitespace.
//        //
//        //   T:System.ArgumentNullException:
//        //     thrown if 'validationParameters is null.
//        //
//        //   T:System.IdentityModel.Tokens.SecurityTokenValidationException:
//        //     thrown if a signature is not found and System.IdentityModel.Tokens.TokenValidationParameters.RequireSignedTokens
//        //     is true.
//        //
//        //   T:System.IdentityModel.Tokens.SecurityTokenSignatureKeyNotFoundException:
//        //     thrown if the 'token' has a key identifier and none of the System.IdentityModel.Tokens.SecurityKey(s)
//        //     provided result in a validated signature. This can indicate that a key refresh
//        //     is required.
//        //
//        //   T:System.IdentityModel.SignatureVerificationFailedException:
//        //     thrown if after trying all the System.IdentityModel.Tokens.SecurityKey(s), none
//        //     result in a validated signture AND the 'token' does not have a key identifier.
//        //
//        //
//        // Remarks:
//        //     If the 'token' is signed, the signature is validated even if System.IdentityModel.Tokens.TokenValidationParameters.RequireSignedTokens
//        //     is false.
//        //
//        //     If the 'token' signature is validated, then the System.IdentityModel.Tokens.JwtSecurityToken.SigningKey
//        //     will be set to the key that signed the 'token'.
//        protected virtual JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
//        {
//            if (string.IsNullOrWhiteSpace(token))
//            {
//                throw new ArgumentNullException("token");
//            }

//            if (validationParameters == null)
//            {
//                throw new ArgumentNullException("validationParameters");
//            }

//            JwtSecurityToken jwtSecurityToken = ReadToken(token) as JwtSecurityToken;
//            byte[] bytes = Encoding.UTF8.GetBytes(jwtSecurityToken.RawHeader + "." + jwtSecurityToken.RawPayload);
//            byte[] array = Base64UrlEncoder.DecodeBytes(jwtSecurityToken.RawSignature);
//            if (array == null)
//            {
//                throw new ArgumentNullException("signatureBytes");
//            }

//            if (array.Length == 0)
//            {
//                if (!validationParameters.RequireSignedTokens)
//                {
//                    return jwtSecurityToken;
//                }

//                throw new SecurityTokenValidationException(string.Format(CultureInfo.InvariantCulture, "IDX10504: Unable to validate signature, token does not have a signature: '{0}'", new object[1] { jwtSecurityToken.ToString() }));
//            }

//            string text = jwtSecurityToken.Header.Alg;
//            if (text != null && InboundAlgorithmMap.ContainsKey(text))
//            {
//                text = InboundAlgorithmMap[text];
//            }

//            SecurityKeyIdentifier signingKeyIdentifier = jwtSecurityToken.Header.SigningKeyIdentifier;
//            if (signingKeyIdentifier.Count > 0)
//            {
//                SecurityKey securityKey = null;
//                if (validationParameters.IssuerSigningKeyResolver != null)
//                {
//                    securityKey = validationParameters.IssuerSigningKeyResolver(token, jwtSecurityToken, signingKeyIdentifier, validationParameters);
//                    if (securityKey == null)
//                    {
//                        throw new SecurityTokenSignatureKeyNotFoundException(string.Format(CultureInfo.InvariantCulture, "IDX10505: Unable to validate signature. The 'Delegate' specified on TokenValidationParameters, returned a null SecurityKey.\nSecurityKeyIdentifier: '{0}'\nToken: '{1}'.", new object[2]
//                        {
//                        signingKeyIdentifier,
//                        jwtSecurityToken.ToString()
//                        }));
//                    }
//                }
//                else
//                {
//                    securityKey = ResolveIssuerSigningKey(token, jwtSecurityToken, signingKeyIdentifier, validationParameters);
//                    if (securityKey == null)
//                    {
//                        throw new SecurityTokenSignatureKeyNotFoundException(string.Format(CultureInfo.InvariantCulture, "IDX10500: Signature validation failed. Unable to resolve SecurityKeyIdentifier: '{0}', \ntoken: '{1}'.", new object[2]
//                        {
//                        signingKeyIdentifier,
//                        jwtSecurityToken.ToString()
//                        }));
//                    }
//                }

//                try
//                {
//                    if (ValidateSignature(bytes, array, securityKey, text))
//                    {
//                        jwtSecurityToken.SigningKey = securityKey;
//                        return jwtSecurityToken;
//                    }
//                }
//                catch (Exception ex)
//                {
//                    throw new SignatureVerificationFailedException(string.Format(CultureInfo.InvariantCulture, "IDX10502: Signature validation failed. Key tried: '{0}'.\nException caught:\n '{1}'.\ntoken: '{2}'", new object[3]
//                    {
//                    CreateKeyString(securityKey),
//                    ex.ToString(),
//                    jwtSecurityToken.ToString()
//                    }), ex);
//                }

//                throw new SignatureVerificationFailedException(string.Format(CultureInfo.InvariantCulture, "IDX10501: Signature validation failed. Key tried: '{0}'.\ntoken: '{1}'", new object[2]
//                {
//                CreateKeyString(securityKey),
//                jwtSecurityToken.ToString()
//                }));
//            }

//            Exception ex2 = null;
//            StringBuilder stringBuilder = new StringBuilder();
//            StringBuilder stringBuilder2 = new StringBuilder();
//            foreach (SecurityKey allKey in GetAllKeys(token, jwtSecurityToken, signingKeyIdentifier, validationParameters))
//            {
//                try
//                {
//                    if (ValidateSignature(bytes, array, allKey, text))
//                    {
//                        jwtSecurityToken.SigningKey = allKey;
//                        return jwtSecurityToken;
//                    }
//                }
//                catch (Exception ex3)
//                {
//                    if (System.IdentityModel.DiagnosticUtility.IsFatal(ex3))
//                    {
//                        throw;
//                    }

//                    if (ex2 == null)
//                    {
//                        ex2 = ex3;
//                    }

//                    stringBuilder.AppendLine(ex3.ToString());
//                }

//                stringBuilder2.AppendLine(CreateKeyString(allKey));
//            }

//            throw new SignatureVerificationFailedException(string.Format(CultureInfo.InvariantCulture, "IDX10503: Signature validation failed. Keys tried: '{0}'.\nExceptions caught:\n '{1}'.\ntoken: '{2}'", new object[3]
//            {
//            stringBuilder2.ToString(),
//            stringBuilder.ToString(),
//            jwtSecurityToken.ToString()
//            }), ex2);
//        }

//        private IEnumerable<SecurityKey> GetAllKeys(string token, SecurityToken securityToken, SecurityKeyIdentifier keyIdentifier, TokenValidationParameters validationParameters)
//        {
//            if (validationParameters.IssuerSigningKeyResolver != null)
//            {
//                yield return validationParameters.IssuerSigningKeyResolver(token, securityToken, keyIdentifier, validationParameters);
//                yield break;
//            }

//            if (validationParameters.IssuerSigningKey != null)
//            {
//                yield return validationParameters.IssuerSigningKey;
//            }

//            if (validationParameters.IssuerSigningKeys != null)
//            {
//                foreach (SecurityKey issuerSigningKey in validationParameters.IssuerSigningKeys)
//                {
//                    yield return issuerSigningKey;
//                }
//            }

//            if (validationParameters.IssuerSigningToken != null)
//            {
//                foreach (SecurityKey securityKey in validationParameters.IssuerSigningToken.SecurityKeys)
//                {
//                    yield return securityKey;
//                }
//            }

//            if (validationParameters.IssuerSigningTokens == null)
//            {
//                yield break;
//            }

//            foreach (SecurityToken t in validationParameters.IssuerSigningTokens)
//            {
//                foreach (SecurityKey securityKey2 in t.SecurityKeys)
//                {
//                    yield return securityKey2;
//                }
//            }
//        }

//        //
//        // Summary:
//        //     Produces a readable string for a key, used in error messages.
//        //
//        // Parameters:
//        //   securityKey:
//        private static string CreateKeyString(SecurityKey securityKey)
//        {
//            if (securityKey == null)
//            {
//                return "null";
//            }

//            return securityKey.ToString();
//        }

//        //
//        // Summary:
//        //     Creates a System.Security.Claims.ClaimsIdentity from a System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        //
//        // Parameters:
//        //   jwt:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken to use as a System.Security.Claims.Claim
//        //     source.
//        //
//        //   issuer:
//        //     The value to set System.Security.Claims.Claim.Issuer
//        //
//        //   validationParameters:
//        //     contains parameters for validating the token.
//        //
//        // Returns:
//        //     A System.Security.Claims.ClaimsIdentity containing the System.IdentityModel.Tokens.JwtSecurityToken.Claims.
//        protected virtual ClaimsIdentity CreateClaimsIdentity(JwtSecurityToken jwt, string issuer, TokenValidationParameters validationParameters)
//        {
//            if (jwt == null)
//            {
//                throw new ArgumentNullException("jwt");
//            }

//            if (string.IsNullOrWhiteSpace(issuer))
//            {
//                throw new ArgumentException("IDX10221: Unable to create claims from securityToken, 'issuer' is null or empty.");
//            }

//            ClaimsIdentity claimsIdentity = validationParameters.CreateClaimsIdentity(jwt, issuer);
//            foreach (Claim claim2 in jwt.Claims)
//            {
//                if (InboundClaimFilter.Contains(claim2.Type))
//                {
//                    continue;
//                }

//                bool flag = true;
//                if (!InboundClaimTypeMap.TryGetValue(claim2.Type, out var value))
//                {
//                    value = claim2.Type;
//                    flag = false;
//                }

//                if (value == "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor")
//                {
//                    if (claimsIdentity.Actor != null)
//                    {
//                        throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "IDX10710: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'", new object[2] { "actort", claim2.Value }));
//                    }

//                    if (CanReadToken(claim2.Value))
//                    {
//                        JwtSecurityToken jwt2 = ReadToken(claim2.Value) as JwtSecurityToken;
//                        claimsIdentity.Actor = CreateClaimsIdentity(jwt2, issuer, validationParameters);
//                    }
//                }

//                Claim claim = new Claim(value, claim2.Value, claim2.ValueType, issuer, issuer, claimsIdentity);
//                if (claim2.Properties.Count > 0)
//                {
//                    foreach (KeyValuePair<string, string> property in claim2.Properties)
//                    {
//                        claim.Properties[property.Key] = property.Value;
//                    }
//                }

//                if (flag)
//                {
//                    claim.Properties[ShortClaimTypeProperty] = claim2.Type;
//                }

//                claimsIdentity.AddClaim(claim);
//            }

//            return claimsIdentity;
//        }

//        //
//        // Summary:
//        //     Creates the 'value' for the actor claim: { actort, 'value' }
//        //
//        // Parameters:
//        //   actor:
//        //     System.Security.Claims.ClaimsIdentity as actor.
//        //
//        // Returns:
//        //     System.String representing the actor.
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     'actor' is null.
//        //
//        // Remarks:
//        //     If System.Security.Claims.ClaimsIdentity.BootstrapContext is not null:
//        //
//        //     if 'type' is 'string', return as string.
//        //
//        //     if 'type' is 'BootstrapContext' and 'BootstrapContext.SecurityToken' is 'JwtSecurityToken'
//        //
//        //
//        //     if 'JwtSecurityToken.RawData' != null, return RawData.
//        //
//        //     else return System.IdentityModel.Tokens.JwtSecurityTokenHandler.WriteToken(System.IdentityModel.Tokens.SecurityToken).
//        //
//        //
//        //     if 'BootstrapContext.Token' != null, return 'Token'.
//        //
//        //     default: System.IdentityModel.Tokens.JwtSecurityTokenHandler.WriteToken(System.IdentityModel.Tokens.SecurityToken)
//        //     new ( System.IdentityModel.Tokens.JwtSecurityToken( actor.Claims ).
//        protected virtual string CreateActorValue(ClaimsIdentity actor)
//        {
//            if (actor == null)
//            {
//                throw new ArgumentNullException("actor");
//            }

//            if (actor.BootstrapContext != null)
//            {
//                if (actor.BootstrapContext is string result)
//                {
//                    return result;
//                }

//                if (actor.BootstrapContext is BootstrapContext bootstrapContext)
//                {
//                    if (bootstrapContext.SecurityToken is JwtSecurityToken jwtSecurityToken)
//                    {
//                        if (jwtSecurityToken.RawData != null)
//                        {
//                            return jwtSecurityToken.RawData;
//                        }

//                        return WriteToken(jwtSecurityToken);
//                    }

//                    if (bootstrapContext.Token != null)
//                    {
//                        return bootstrapContext.Token;
//                    }
//                }
//            }

//            return WriteToken(new JwtSecurityToken(null, null, actor.Claims));
//        }

//        //
//        // Summary:
//        //     Determines if the audiences found in a System.IdentityModel.Tokens.JwtSecurityToken
//        //     are valid.
//        //
//        // Parameters:
//        //   audiences:
//        //     The audiences found in the System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        //   securityToken:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken being validated.
//        //
//        //   validationParameters:
//        //     System.IdentityModel.Tokens.TokenValidationParameters required for validation.
//        //
//        //
//        // Remarks:
//        //     see System.IdentityModel.Tokens.Validators.ValidateAudience(System.Collections.Generic.IEnumerable{System.String},System.IdentityModel.Tokens.SecurityToken,System.IdentityModel.Tokens.TokenValidationParameters)
//        //     for additional details.
//        protected virtual void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
//        {
//            Validators.ValidateAudience(audiences, securityToken, validationParameters);
//        }

//        //
//        // Summary:
//        //     Validates the lifetime of a System.IdentityModel.Tokens.JwtSecurityToken.
//        //
//        // Parameters:
//        //   notBefore:
//        //     The System.DateTime value of the 'nbf' claim if it exists in the 'jwt'.
//        //
//        //   expires:
//        //     The System.DateTime value of the 'exp' claim if it exists in the 'jwt'.
//        //
//        //   securityToken:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken being validated.
//        //
//        //   validationParameters:
//        //     System.IdentityModel.Tokens.TokenValidationParameters required for validation.
//        //
//        //
//        // Remarks:
//        //     System.IdentityModel.Tokens.Validators.ValidateLifetime(System.Nullable{System.DateTime},System.Nullable{System.DateTime},System.IdentityModel.Tokens.SecurityToken,System.IdentityModel.Tokens.TokenValidationParameters)
//        //     for additional details.
//        protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
//        {
//            Validators.ValidateLifetime(notBefore, expires, securityToken, validationParameters);
//        }

//        //
//        // Summary:
//        //     Determines if an issuer found in a System.IdentityModel.Tokens.JwtSecurityToken
//        //     is valid.
//        //
//        // Parameters:
//        //   issuer:
//        //     The issuer to validate
//        //
//        //   securityToken:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken that is being validated.
//        //
//        //   validationParameters:
//        //     System.IdentityModel.Tokens.TokenValidationParameters required for validation.
//        //
//        //
//        // Returns:
//        //     The issuer to use when creating the System.Security.Claims.Claim(s) in the System.Security.Claims.ClaimsIdentity.
//        //
//        //
//        // Remarks:
//        //     System.IdentityModel.Tokens.Validators.ValidateIssuer(System.String,System.IdentityModel.Tokens.SecurityToken,System.IdentityModel.Tokens.TokenValidationParameters)
//        //     for additional details.
//        protected virtual string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
//        {
//            return Validators.ValidateIssuer(issuer, securityToken, validationParameters);
//        }

//        //
//        // Summary:
//        //     Returns a System.IdentityModel.Tokens.SecurityKey to use when validating the
//        //     signature of a token.
//        //
//        // Parameters:
//        //   token:
//        //     the System.String representation of the token that is being validated.
//        //
//        //   securityToken:
//        //     the that is being validated.
//        //
//        //   keyIdentifier:
//        //     the System.IdentityModel.Tokens.SecurityKeyIdentifier found in the token.
//        //
//        //   validationParameters:
//        //     A System.IdentityModel.Tokens.TokenValidationParameters required for validation.
//        //
//        //
//        // Returns:
//        //     Returns a System.IdentityModel.Tokens.SecurityKey to use for signature validation.
//        //
//        //
//        // Exceptions:
//        //   T:System.ArgumentNullException:
//        //     if 'keyIdentifier' is null.
//        //
//        //   T:System.ArgumentNullException:
//        //     if 'validationParameters' is null.
//        //
//        // Remarks:
//        //     If key fails to resolve, then null is returned
//        protected virtual SecurityKey ResolveIssuerSigningKey(string token, SecurityToken securityToken, SecurityKeyIdentifier keyIdentifier, TokenValidationParameters validationParameters)
//        {
//            if (keyIdentifier == null)
//            {
//                throw new ArgumentNullException("keyIdentifier");
//            }

//            if (validationParameters == null)
//            {
//                throw new ArgumentNullException("validationParameters");
//            }

//            foreach (SecurityKeyIdentifierClause item in keyIdentifier)
//            {
//                CertMatcher certMatcher = null;
//                if (item is X509RawDataKeyIdentifierClause @object)
//                {
//                    certMatcher = @object.Matches;
//                }
//                else if (item is X509SubjectKeyIdentifierClause object2)
//                {
//                    certMatcher = object2.Matches;
//                }
//                else if (item is X509ThumbprintKeyIdentifierClause object3)
//                {
//                    certMatcher = object3.Matches;
//                }
//                else if (item is X509IssuerSerialKeyIdentifierClause object4)
//                {
//                    certMatcher = object4.Matches;
//                }

//                if (validationParameters.IssuerSigningKey != null)
//                {
//                    SecurityToken token2 = null;
//                    if (Matches(item, validationParameters.IssuerSigningKey, certMatcher, out token2))
//                    {
//                        return validationParameters.IssuerSigningKey;
//                    }
//                }

//                if (validationParameters.IssuerSigningKeys != null)
//                {
//                    foreach (SecurityKey issuerSigningKey in validationParameters.IssuerSigningKeys)
//                    {
//                        SecurityToken token3 = null;
//                        if (Matches(item, issuerSigningKey, certMatcher, out token3))
//                        {
//                            return issuerSigningKey;
//                        }
//                    }
//                }

//                if (validationParameters.IssuerSigningToken != null && validationParameters.IssuerSigningToken.MatchesKeyIdentifierClause(item))
//                {
//                    return validationParameters.IssuerSigningToken.SecurityKeys[0];
//                }

//                if (validationParameters.IssuerSigningTokens == null)
//                {
//                    continue;
//                }

//                foreach (SecurityToken issuerSigningToken in validationParameters.IssuerSigningTokens)
//                {
//                    if (issuerSigningToken.MatchesKeyIdentifierClause(item))
//                    {
//                        return issuerSigningToken.SecurityKeys[0];
//                    }
//                }
//            }

//            return null;
//        }

//        private static bool Matches(SecurityKeyIdentifierClause keyIdentifierClause, SecurityKey key, CertMatcher certMatcher, out SecurityToken token)
//        {
//            token = null;
//            if (certMatcher != null)
//            {
//                if (key is X509SecurityKey x509SecurityKey)
//                {
//                    if (certMatcher(x509SecurityKey.Certificate))
//                    {
//                        token = new X509SecurityToken(x509SecurityKey.Certificate);
//                        return true;
//                    }
//                }
//                else if (key is X509AsymmetricSecurityKey obj && _certFieldInfo.GetValue(obj) is X509Certificate2 x509Certificate && certMatcher(x509Certificate))
//                {
//                    token = new X509SecurityToken(x509Certificate);
//                    return true;
//                }
//            }

//            return false;
//        }

//        //
//        // Summary:
//        //     Validates the System.IdentityModel.Tokens.JwtSecurityToken.SigningKey is an expected
//        //     value.
//        //
//        // Parameters:
//        //   securityKey:
//        //     The System.IdentityModel.Tokens.SecurityKey that signed the System.IdentityModel.Tokens.SecurityToken.
//        //
//        //
//        //   securityToken:
//        //     The System.IdentityModel.Tokens.JwtSecurityToken to validate.
//        //
//        //   validationParameters:
//        //     the current System.IdentityModel.Tokens.TokenValidationParameters.
//        //
//        // Remarks:
//        //     If the System.IdentityModel.Tokens.JwtSecurityToken.SigningKey is a System.IdentityModel.Tokens.X509SecurityKey
//        //     then the X509Certificate2 will be validated using System.IdentityModel.Tokens.TokenValidationParameters.CertificateValidator.
//        protected virtual void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
//        {
//            Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
//        }
//    }
//}