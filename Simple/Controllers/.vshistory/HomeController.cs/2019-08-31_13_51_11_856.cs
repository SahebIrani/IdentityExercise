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
            UserManager<User> userManager)
        {
            Logger = logger;
            UserManager = userManager;
        }
        public ILogger<HomeController> Logger { get; }
        public UserManager<User> UserManager { get; }

        public IActionResult Index()
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
