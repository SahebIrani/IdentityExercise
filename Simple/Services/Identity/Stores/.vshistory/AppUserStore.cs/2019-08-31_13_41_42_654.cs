using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

using Simple.Data;
using Simple.Models.Entities.Identity;

namespace Simple.Services.Identity.Stores
{
    public class AppUserStore : UserStore<User, Role, ApplicationDbContext, int, UserClaim, UserRole, UserLogin, UserToken, RoleClaim>
    {
        public AppUserStore(ApplicationDbContext context, IdentityErrorDescriber describer = null) : base(
            context,
            describer)
        {
        }
    }
}