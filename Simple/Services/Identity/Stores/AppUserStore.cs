using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

using Simple.Data;
using Simple.Models.Entities.Identity;

using System.Threading;
using System.Threading.Tasks;

namespace Simple.Services.Identity.Stores
{
    public class AppUserStore : UserStore<User, Role, ApplicationDbContext, int, UserClaim, UserRole, UserLogin, UserToken, RoleClaim>
    {
        public AppUserStore(
            ApplicationDbContext context,
            IdentityErrorDescriber describer = null) : base(
                context,
                describer)
        {
        }
        public override async Task<User> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
        {
            //return base.FindByEmailAsync(normalizedEmail, cancellationToken);
            User user = await Context.Users.AsNoTracking().SingleOrDefaultAsync(c => c.Email == normalizedEmail, cancellationToken);
            return user;
        }
    }
}