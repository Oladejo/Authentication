using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;

namespace Basic.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        public IActionResult Authenticate()
        {
            var heyzedClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Azeez"),
                new Claim(ClaimTypes.Email, "heyzed@gmail.com"),
                new Claim("Grandma.says", "Very nice boy"),
            };

            var licenseClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Arewa"),
                new Claim("DrivingLicense", "A+"),
            };

            var heyzedIdentity = new ClaimsIdentity(heyzedClaims, "Heyzed Identity");
            var licenseIdentity = new ClaimsIdentity(licenseClaims, "Heyzed License");
             
            var userPrincipal = new ClaimsPrincipal(new[] { heyzedIdentity, licenseIdentity });

            HttpContext.SignInAsync(userPrincipal);

            return RedirectToAction("Index");
        }
    }
}
