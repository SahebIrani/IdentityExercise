using Microsoft.AspNetCore.Identity;

using System;
using System.Collections.Generic;

namespace Simple.Models.Entities.Identity
{
    public class Role : IdentityRole<int>
    {
        public string DisplayName { get; set; }

        public DateTime CreatedOn { get; set; }

        public ICollection<RoleClaim> Claims { get; set; }

        public ICollection<UserRole> Users { get; set; }

    }
}