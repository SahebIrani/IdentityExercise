using Microsoft.AspNetCore.Identity;

using Simple.Models.Entities.Identity;

using System.Threading.Tasks;

namespace Simple.Services.Identity.Validators
{
    public class AppRoleValidator : RoleValidator<Role>
    {
        public AppRoleValidator(IdentityErrorDescriber errors) : base(errors)
        {
        }

        public override Task<IdentityResult> ValidateAsync(RoleManager<Role> manager, Role role)
        {
            return base.ValidateAsync(manager, role);
        }
    }
}