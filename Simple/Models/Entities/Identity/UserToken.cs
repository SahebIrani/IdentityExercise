
using Microsoft.AspNetCore.Identity;

namespace Simple.Models.Entities.Identity
{
    public class UserToken : IdentityUserToken<int>
    {
        public User User { get; set; }
    }
}