using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

using Simple.Models.Entities.Identity;

using System.Collections.Generic;

namespace Simple.Services.Identity.Managers
{
    public class AppRoleManager : RoleManager<Role>
    {
        public AppRoleManager(IRoleStore<Role> store,
                              IEnumerable<IRoleValidator<Role>> roleValidators,
                              ILookupNormalizer keyNormalizer,
                              IdentityErrorDescriber errors,
                              ILogger<RoleManager<Role>> logger) : base(store, roleValidators, keyNormalizer, errors, logger)
        {
        }
    }
}