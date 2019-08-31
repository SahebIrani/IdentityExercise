using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Simple.Models.Entities.Identity;

using System.Threading.Tasks;

namespace Simple.Services.Identity.Managers
{
    public class AppSignInManager : SignInManager<User>
    {
        public AppSignInManager(
            UserManager<User> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<User> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<User>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<User> userConfirmation)
            : base(
                  userManager,
                  contextAccessor,
                  claimsFactory,
                  optionsAccessor,
                  logger,
                  schemes,
                  userConfirmation)
        {
        }

        public override Task<SignInResult> CheckPasswordSignInAsync(User user, string password, bool lockoutOnFailure)
        {


            return base.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
        }
    }
}