using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebNet4_8.App_Start.OidcSecurity
{
    public interface ITokenReplayCache
    {
        //
        // Summary:
        //     Try to add a securityToken.
        //
        // Parameters:
        //   securityToken:
        //     the security token to add.
        //
        //   expiresOn:
        //     the time when security token expires.
        //
        // Returns:
        //     true if the security token was successfully added.
        bool TryAdd(string securityToken, DateTime expiresOn);

        //
        // Summary:
        //     Try to find securityToken
        //
        // Parameters:
        //   securityToken:
        //     the security token to find.
        //
        // Returns:
        //     true if the security token is found.
        bool TryFind(string securityToken);
    }
}