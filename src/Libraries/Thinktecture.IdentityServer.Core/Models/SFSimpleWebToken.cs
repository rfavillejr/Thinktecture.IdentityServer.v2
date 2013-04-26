using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Helper;
using Thinktecture.IdentityModel.Tokens;
using Thinktecture.IdentityModel.Extensions;
using System.Security.Cryptography;
using System.Web;
using System.ComponentModel.Composition;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Models
{
    public class SFSimpleWebToken : SecurityToken
    {
        [Import]
        public IRelyingPartyRepository RelyingPartyRepository { get; set; }

        /// <summary>
        /// Creates a new instance of SimpleWebToken and optionally parses it
        /// </summary>
        /// <param name="rawToken">URL decoded SWT</param>
        /// <param name="autoParse">true if parsing is required, otherwise false.</param>
        public SFSimpleWebToken(string rawToken)
        {
            Container.Current.SatisfyImportsOnce(this);
            this.RawToken = rawToken;
            this.EnsureProperties();
        }

        public SFSimpleWebToken(SimpleWebToken swt)
        {
            Container.Current.SatisfyImportsOnce(this);
            this.RawToken = WriteToken(swt);
            this.EnsureProperties();
        }

        public string RawToken { get; private set; }

        public override string Id
        {
            get
            {
                return this.tokenId;
            }
        }

        public override System.Collections.ObjectModel.ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get { return new List<SecurityKey>().AsReadOnly(); }
        }

        public override DateTime ValidFrom
        {
            get
            {
                return this.validFrom;
            }
        }

        public override DateTime ValidTo
        {
            get
            {
                return this.validTo;
            }
        }

        public string Issuer
        {
            get
            {
                return this.issuer;
            }
        }

        public string Audience
        {
            get
            {
                return this.audience;
            }
        }

        public IList<Claim> Claims
        {
            get
            {
                return this.claims;
            }
        }

        void EnsureProperties()
        {
            var parser = new SFParser(this.RawToken);

            this.issuer = parser.Issuer;
            this.audience = parser.Audience;
            this.validFrom = parser.ValidFrom;
            this.validTo = parser.ExpiresOn;
            this.claims = parser.Claims;
            this.tokenId = parser.TokenId;
        }

        private string WriteToken(SimpleWebToken swt)
        {

            if (swt == null)
            {
                throw new InvalidOperationException("token");
            }

            var unsignedToken = CreateUnsignedToken(swt);

            var RP = RelyingPartyRepository.List(0, 100).First( b => b.Realm == swt.AudienceUri);

            var hexString = Convert.ToBase64String(RP.SymmetricSigningKey);

            var hmac = new HMACSHA256(SFHelper.HexToByte(hexString));
            var sig = hmac.ComputeHash(Encoding.ASCII.GetBytes(unsignedToken));

            var signedToken = String.Format("{0}&HMACSHA256={1}",
                unsignedToken,
                HttpUtility.UrlEncode(Convert.ToBase64String(sig)));

            return signedToken;
        }

        private static string CreateUnsignedToken(SimpleWebToken swt)
        {
            var sb = new StringBuilder();
            var claims = new Dictionary<string, string>();

            foreach (var claim in swt.Claims)
            {
                claims.Add(claim.Type, claim.Value);
            }

            foreach (var kv in claims)
            {
                sb.AppendFormat("{0}={1}&", HttpUtility.UrlEncode(kv.Key), HttpUtility.UrlEncode(kv.Value));
            }

            sb.AppendFormat("TokenId={0}&", HttpUtility.UrlEncode(Guid.NewGuid().ToString()));
            sb.AppendFormat("Issuer={0}&", HttpUtility.UrlEncode(swt.Issuer));
            sb.AppendFormat("Audience={0}&", HttpUtility.UrlEncode(swt.AudienceUri.AbsoluteUri));
            sb.AppendFormat("ExpiresOn={0:0}", swt.ValidTo.ToEpochTime());

            return sb.ToString();
        }

        //public override string ToString()
        //{
        //    return string.Format("tokeId = {0}, issuer = {1}, audience = {2}, validFrom = {3}, validTo = {4}, claims = {5}", tokenId, issuer, audience, claims.ToArray().Aggregate("", (s, i) => s + i.Type + ", " + i.Value));
        //}

        private string tokenId;
        private string issuer;
        private string audience;
        private DateTime validFrom;
        private DateTime validTo;
        private IList<Claim> claims;
    }
}
