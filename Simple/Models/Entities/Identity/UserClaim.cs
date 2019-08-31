using Microsoft.AspNetCore.Identity;

namespace Simple.Models.Entities.Identity
{
    public class UserClaim : IdentityUserClaim<int>
    {
        public User User { get; set; }
    }
}