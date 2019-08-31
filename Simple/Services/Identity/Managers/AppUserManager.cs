using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Simple.Models.Entities.Identity;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Simple.Services.Identity.Managers
{
    public class AppUserManager : UserManager<User>
    {
        public AppUserManager(
            IUserStore<User> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<User> passwordHasher,
            IEnumerable<IUserValidator<User>> userValidators,
            IEnumerable<IPasswordValidator<User>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<User>> logger) : base(
                store,
                optionsAccessor,
                passwordHasher,
                userValidators,
                passwordValidators,
                keyNormalizer,
                errors,
                services,
                logger)
        {
        }

        public override Task<IdentityResult> ResetPasswordAsync(User user, string token, string newPassword)
        {
            return base.ResetPasswordAsync(user, token, newPassword);
        }
    }
}