using Microsoft.AspNetCore.Identity;

namespace Simple.Models.Entities.Identity
{
    public class RoleClaim : IdentityRoleClaim<int>
    {
        public Role Role { get; set; }
    }
}