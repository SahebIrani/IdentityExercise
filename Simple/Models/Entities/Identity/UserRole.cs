using Microsoft.AspNetCore.Identity;

namespace Simple.Models.Entities.Identity
{
    public class UserRole : IdentityUserRole<int>
    {
        public User User { get; set; }

        public Role Role { get; set; }
    }
}