using Microsoft.AspNetCore.Identity;

using System;

namespace Simple.Models.Entities.Identity
{
    public class RoleClaim : IdentityRoleClaim<int>
    {
        public DateTime GivenOn { get; set; }

        public Role Role { get; set; }
    }
}