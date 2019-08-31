using Microsoft.AspNetCore.Identity;

namespace Simple.Models.Entities.Identity
{
    public class UserLogin : IdentityUserLogin<int>
    {
        public User User { get; set; }
    }
}