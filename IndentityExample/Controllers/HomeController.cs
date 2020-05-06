using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using NETCore.MailKit.Core;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace IndentityExample.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailService _emailService;

        public HomeController(UserManager<IdentityUser> userManager,  
             SignInManager<IdentityUser> signInManager,
             IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
        }

        public IActionResult Index() => View();

        [Authorize]
        public IActionResult Secret() => View();

        public IActionResult Login() => View();
        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            //Login functionality
            var user = await _userManager.FindByNameAsync(username);

            if (user != null)
            {
                var signInResult = await _signInManager.PasswordSignInAsync(username, password, false, false);

                if (signInResult.Succeeded)
                {
                    return RedirectToAction("Secret");
                }
            }
            
            return RedirectToAction("Index");
        }

        public IActionResult Register() => View();

        [HttpPost]
        public async Task<IActionResult>  Register(string username, string password)
        {
            if(string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) { return BadRequest(); }

            var checkUser = await _userManager.FindByNameAsync(username);
            if(checkUser != null) { return BadRequest();  }

            //Register functionality
            var user = new IdentityUser
            {
                UserName = username,
                Email = username
            };

            var result = await _userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                //check if Email is confirmation is required
                if (_userManager.Options.SignIn.RequireConfirmedEmail)
                {
                    //generation of email token
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                    var link = Url.Action(nameof(VerifyEmail), "Home", new { userId = user.Id, code }, Request.Scheme, Request.Host.ToString());

                    var emailVerificationHtml = $"<a href='{HtmlEncoder.Default.Encode(link)}'>Verify Email Address!</a>";

                    await _emailService.SendAsync("test@test.com", "Email verification", emailVerificationHtml, true);

                    return RedirectToAction("EmailVerification");
                }
                else
                {
                    //login the user
                    var signInUser = await _signInManager.PasswordSignInAsync(user, password, false, false);
                    if(! signInUser.Succeeded) { return BadRequest();  }

                    return RedirectToAction("Secret");
                }
            }

            return RedirectToAction("Index");
        }

        public IActionResult EmailVerification() => View();
             
        public async Task<IActionResult> VerifyEmail(string userId,  string code)
        {
            if(string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code)) { return RedirectToAction("Index");  }

            var user = await _userManager.FindByIdAsync(userId);
            if(user != null)
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

                var result =  await _userManager.ConfirmEmailAsync(user, code);

                if (result.Succeeded)
                {
                    return View();
                }
            }

            return BadRequest();
        }
                
        public  async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index");
        }

        //Forgot Password

    }
}
