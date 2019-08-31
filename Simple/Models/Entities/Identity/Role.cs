using Microsoft.AspNetCore.Identity;

using System.Collections.Generic;

namespace Simple.Models.Entities.Identity
{
    public class Role : IdentityRole<int>
    {
        public string DisplayName { get; set; }

        public ICollection<RoleClaim> Claims { get; set; }

        public ICollection<UserRole> Users { get; set; }
    }
}