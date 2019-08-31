using Microsoft.AspNetCore.Identity;

using Simple.Models.Entities.Identity;

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Simple.Services.Identity.Validators
{
    public class AppUserValidator : UserValidator<User>
    {
        public AppUserValidator(IdentityErrorDescriber errors) : base(errors)
        {
        }

        public override async Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user)
        {
            var result = await base.ValidateAsync(manager, user);

            ValidateUserName(user, result.Errors.ToList());

            return result;
        }


        private void ValidateUserName(User user, List<IdentityError> errors)
        {
            if (user.UserName.Contains("SinjulMSBH"))
            {
                errors.Add(new IdentityError
                {
                    Code = "InvalidUser",
                    Description = "چنین کاربری مجاز نیست"
                });
            }
        }
    }
}