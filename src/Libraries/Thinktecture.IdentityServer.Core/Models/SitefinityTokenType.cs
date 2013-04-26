using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Thinktecture.IdentityServer.Models
{
    public class SitefinityTokenRequest
    {
        [Required]
        public string Realm { get; set; }
        [Required]
        public string Redirect_Uri { get; set; }
        public bool Deflate { get; set; }
        public override string ToString()
        {
            return string.Format("Realm = {0}, Redirect_Uri = {1}, Deflate = {2}", Realm, Redirect_Uri, Deflate);
        }
    }
}
