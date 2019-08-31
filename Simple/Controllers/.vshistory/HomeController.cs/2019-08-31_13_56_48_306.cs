using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using Simple.Models;
using Simple.Models.Entities.Identity;

using System.Diagnostics;

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

            IUserValidator<User> userValidator,
            IRoleValidator<User> roleValidator
        )
        {
            Logger = logger;
            UserManager = userManager;
            RoleManager = roleManager;
            SignInManager = signInManager;
            UserStore = userStore;
            RoleStore = roleStore;
            UserValidator = userValidator;
            RoleValidator = roleValidator;
        }

        public ILogger<HomeController> Logger { get; }
        public UserManager<User> UserManager { get; }
        public RoleManager<Role> RoleManager { get; }
        public SignInManager<User> SignInManager { get; }
        public IUserStore<User> UserStore { get; }
        public IRoleStore<Role> RoleStore { get; }
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


        public IActionResult ResetPassword()
        {
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
