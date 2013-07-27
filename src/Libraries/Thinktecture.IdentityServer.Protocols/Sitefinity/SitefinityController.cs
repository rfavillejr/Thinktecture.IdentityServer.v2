/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.Composition;
using System.IdentityModel.Services;
using System.Security.Claims;
using System.Web;
using System.Linq;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;
using System.IdentityModel.Protocols.WSTrust;
using Thinktecture.IdentityServer.Models;
using System.Net;
using System;
using Thinktecture.IdentityModel.Constants;
using System.Collections.Specialized;
using Thinktecture.IdentityServer.Helper;
using System.IdentityModel.Tokens;
using Thinktecture.IdentityModel.Tokens;

namespace Thinktecture.IdentityServer.Protocols.Sitefinity
{
    [ClaimsAuthorize(Constants.Actions.Issue, Constants.Resources.Sitefinity, Roles="IdentityServerUsers")]
    public class SitefinityController : Controller
    {
        const string _cookieName = "wsfedsignout";
        readonly HttpContext _currrenContext;

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public SitefinityController()
        {
            _currrenContext = System.Web.HttpContext.Current;
            Container.Current.SatisfyImportsOnce(this);
        }

        public SitefinityController(IConfigurationRepository configurationRepository)
        {
            ConfigurationRepository = configurationRepository;
        }

        public ActionResult Issue()
        {
            Tracing.Verbose("Sitefinity endpoint called.");

            var query = _currrenContext.Request.QueryString;

            var realm = query[query.AllKeys.FirstOrDefault(p => p.Equals("realm", System.StringComparison.OrdinalIgnoreCase))];
            var tokenType = query[query.AllKeys.FirstOrDefault(p => p.Equals("tokenType", System.StringComparison.OrdinalIgnoreCase))];
            var reply = query[query.AllKeys.FirstOrDefault(p => p.Equals("redirect_uri", System.StringComparison.OrdinalIgnoreCase))];
            var deflateTemp = query[query.AllKeys.FirstOrDefault(p => p.Equals("deflate", System.StringComparison.OrdinalIgnoreCase))];
            var isSignout = query[query.AllKeys.FirstOrDefault(p => p.Equals("sign_out", System.StringComparison.OrdinalIgnoreCase))];

            //if this is a signout request, sign out the user and redirect
            if (!string.IsNullOrWhiteSpace(isSignout))
            {
                Tracing.Verbose("Sitefinity signout request detected - signout var = " + isSignout);
                if (isSignout.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    Tracing.Verbose("Sitefinity logout request");
                    FederatedAuthentication.SessionAuthenticationModule.SignOut();
                    return Redirect((new Uri(new Uri(realm), reply)).AbsoluteUri);
                }
            }

            if (string.IsNullOrWhiteSpace(deflateTemp))
                deflateTemp = "false";

            var deflate = "true".Equals(deflateTemp, StringComparison.OrdinalIgnoreCase);

            Tracing.Verbose("Sitefinity query string parsed");

            if (string.IsNullOrWhiteSpace(realm))
            {
                Tracing.Error("Malformed realm: " + realm);
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest, "realm parameter is missing.");
            }

            EndpointReference appliesTo;
            try
            {
                appliesTo = new EndpointReference(realm);
                Tracing.Information("Sitefinity Simple HTTP endpoint called for realm: " + realm);
            }
            catch
            {
                Tracing.Error("Malformed realm: " + realm);
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest, "malformed realm name.");// request.CreateErrorResponse(HttpStatusCode.BadRequest, "malformed realm name.");
            }

            if (string.IsNullOrWhiteSpace(tokenType))
                tokenType = TokenTypes.SimpleWebToken;


            Tracing.Verbose("Sitefinity Token type: " + tokenType);
            Tracing.Verbose("Sitefinity Current Claims Principal: " + ClaimsPrincipal.Current.Claims.ToString() + ", " + ClaimsPrincipal.Current.Identity.Name + ", " + appliesTo.Uri + ", " + appliesTo.Details.ToString());

            SecurityToken tokenResponse;
            var sts = new STS();
            if (sts.TryIssueToken(appliesTo, ClaimsPrincipal.Current, tokenType, out tokenResponse))
            {

                NameValueCollection queryString;
                if (tokenResponse != null)
                    Tracing.Verbose(string.Join(", ", "UID: " + tokenResponse.Id));
                else
                    Tracing.Error("Token is null after being issued");
                var token = new SFSimpleWebToken(tokenResponse as SimpleWebToken);
                //if (token != null)
                //    Tracing.Verbose("Sitefinity Token: " + token.ToString());
                //else
                //    Tracing.Error("Sitefinity Token is null");
                try
                {
                    if (!String.IsNullOrEmpty(reply))
                    {
                        string path;
                        var issuer = HttpContext.Request.Url.AbsoluteUri;
                        var idx = issuer.IndexOf("?");
                        idx = reply.IndexOf('?');
                        if (idx != -1)
                        {
                            path = reply.Substring(0, idx);
                            queryString = HttpUtility.ParseQueryString(reply.Substring(idx + 1));
                        }
                        else
                        {
                            path = reply;
                            queryString = new NameValueCollection();
                        }
                        Tracing.Verbose("Begin wrapping SWT");
                        SFHelper.WrapSWT(queryString, token, deflate);
                        Tracing.Verbose("Begin building path and query for return url");
                        path = String.Concat(path, SFHelper.ToQueryString(queryString));
                        var uri = new Uri(new Uri(realm), path);
                        return Redirect(uri.AbsoluteUri);
                    }

                    queryString = new NameValueCollection();
                    SFHelper.WrapSWT(queryString, token, deflate);
                    return File(SFHelper.ToQueryString(queryString), "application/x-www-form-urlencoded", "token");
                }
                catch (Exception e)
                {
                    Tracing.Error(e.Message + " " + e.InnerException);
                    Tracing.Error("invalid request - token couldn't issue for realm " + realm);
                    return new HttpStatusCodeResult(HttpStatusCode.BadRequest, "invalid request.");
                }
            }
            else
            {
                Tracing.Error("invalid request - token couldn't issue for realm " + realm);
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest, "invalid request.");
            }
        }
    }
}
