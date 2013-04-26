using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Repositories.Sql.Configuration
{
    public class SitefinityConfiguration
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public bool Enabled { get; set; }
    }
}
