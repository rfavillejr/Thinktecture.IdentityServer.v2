﻿/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.Web.Mvc;

namespace Thinktecture.IdentityServer.Protocols.Sitefinity
{
    public class SitefinityResult : ContentResult
    {
        public SitefinityResult(SignInResponseMessage message, bool requireSsl)
        {
            if (requireSsl)
            {
                if (message.BaseUri.Scheme != Uri.UriSchemeHttps)
                {
                    throw new InvalidRequestException(Resources.WSFederation.WSFederationResult.ReturnUrlMustBeSslException);
                }
            }

            Content = message.WriteFormPost();
        }
    }
}