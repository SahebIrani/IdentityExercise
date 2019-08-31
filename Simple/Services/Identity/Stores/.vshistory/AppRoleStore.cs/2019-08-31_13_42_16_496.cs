using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

using Simple.Data;
using Simple.Models.Entities.Identity;

namespace Simple.Services.Identity.Stores
{
    public class AppRoleStore : RoleStore<Role, ApplicationDbContext, int, UserRole, RoleClaim>
    {
        public AppRoleStore(
            ApplicationDbContext context,
            IdentityErrorDescriber describer = null) : base(context, describer)
        {
        }
    }
}