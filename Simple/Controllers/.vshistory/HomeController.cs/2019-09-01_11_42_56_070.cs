using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using Simple.Models;
using Simple.Models.Entities.Identity;

using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Simple.Controllers
{
    public class HomeController : Controller
    {
        public HomeController(
            ILogger<HomeController> logger,

            UserManager<User> userManager,
            RoleManager<Role> roleManager,
            SignInManager<User> signInManager,

            IUserStore<User> userStore,
            IRoleStore<Role> roleStore,

            IPasswordHasher<User> passwordHasher,
            IPasswordValidator<User> passwordValidator,

            IUserPasswordStore<User> passwordStore

        //IUserValidator<User> userValidator,
        //IRoleValidator<User> roleValidator
        )
        {
            Logger = logger;
            UserManager = userManager;
            RoleManager = roleManager;
            SignInManager = signInManager;
            UserStore = userStore;
            RoleStore = roleStore;
            PasswordHasher = passwordHasher;
            PasswordValidator = passwordValidator;
            PasswordStore = passwordStore;
            //UserValidator = userValidator;
            //RoleValidator = roleValidator;
        }

        public ILogger<HomeController> Logger { get; }
        public UserManager<User> UserManager { get; }
        public RoleManager<Role> RoleManager { get; }
        public SignInManager<User> SignInManager { get; }
        public IUserStore<User> UserStore { get; }
        public IRoleStore<Role> RoleStore { get; }
        public IPasswordHasher<User> PasswordHasher { get; }
        public IPasswordValidator<User> PasswordValidator { get; }
        public IUserPasswordStore<User> PasswordStore { get; }
        public IUserValidator<User> UserValidator { get; }
        public IRoleValidator<User> RoleValidator { get; }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult LoginUser()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> LoginUserAsync(
            string email = "admin@test.com",
            string password = "@GD3sg1546sy%#@ds&&sgD^as",
            CancellationToken cancellationToken = default)
        {
            User user = await UserManager.FindByEmailAsync(email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "لطفا از صحت اطلاعات وارد شده اطمینان حاصل کنید");
                return View();
            }

            var passwordHash = UserManager.PasswordHasher.HashPassword(user, password);
            var newPasswordHash = PasswordHasher.HashPassword(user, password);
            var newPasswordHash1 = PasswordHasher.HashPassword(user, password);

            var passwordResult = await PasswordValidator.ValidateAsync(UserManager, user, password);
            var newPasswordHash2 = PasswordHasher.HashPassword(user, password);
            await PasswordStore.SetPasswordHashAsync(user, password, cancellationToken);

            var checkPassSignIn = await SignInManager.CheckPasswordSignInAsync(user, password, true);
            if (checkPassSignIn.Succeeded)
            {
                //این متد PasswordSignInAsync تو خودش از متد بالایی یعنی CheckPasswordSignInAsync استفاده میکنه
                var result = await SignInManager.PasswordSignInAsync(email, password, true, false);
                if (result.Succeeded) RedirectToAction(nameof(Index));
                else
                {
                    ModelState.AddModelError(string.Empty, "اطلاعات وارد شده صحیح نمی باشد");
                    return View();
                }
            }

            return View();
        }


        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPasswordAsync(
            string code,
            string email = "admin@test.com",
            string password = "@GD3sg1546sy%#@ds&&sgD^as",
            CancellationToken cancellationToken = default
        )
        {
            User user = await UserManager.FindByEmailAsync(email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "کاربر نا معتبر");
                return View();
            }

            user.PasswordHash = UserManager.PasswordHasher.HashPassword(user, password);
            var resultt = await UserManager.UpdateAsync(user);
            if (!resultt.Succeeded)
            {
            }

            var token = await UserManager.GeneratePasswordResetTokenAsync(user);
            var resulttt = await UserManager.ResetPasswordAsync(user, token, password);

            IdentityResult result = await UserManager.ResetPasswordAsync(user, code, password);
            if (result.Succeeded)
                return RedirectToAction(nameof(ResetPassword));

            foreach (IdentityError error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
