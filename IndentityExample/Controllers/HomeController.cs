using IndentityExample.Model;
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

                    // Send email through EmailService (MailKit NetCore) 
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

        public IActionResult ForgotPassword() => View();

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            if(string.IsNullOrEmpty(email)) { return BadRequest(); }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) { return BadRequest(); }

            // Generate Password Token
            var passwordToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            passwordToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(passwordToken));

            // Generate Password Reset Url
            var passwordResetUrl = Url.Action(nameof(ResetPassword), "Home",
                    new { userId = user.Id, passwordToken },
                    Request.Scheme,
                    Request.Host.ToString());

            // Generate an HTML Link from Verification URL
            var passwordResetHtml = $"<a href='{HtmlEncoder.Default.Encode(passwordResetUrl)}'>Click here to reset your password!</a>";

            // Send email through EmailService (MailKit NetCore)
            await _emailService.SendAsync("test@test.com", "Password Reset Request", passwordResetHtml, true);

            return RedirectToAction("ForgotPasswordEmailSent");
        }

        public IActionResult ForgotPasswordEmailSent() => View();

        [HttpGet()]
        public IActionResult ResetPassword(string userId, string passwordToken)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(passwordToken)) { return RedirectToAction("Index"); }

            passwordToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(passwordToken));

            return View(new ResetPassword { UserId = userId, Token = passwordToken }); // Passing in the ViewModel.
        }

        [HttpPost()]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword) // Receiving the ViewModel from post.
        {
            if (!ModelState.IsValid) { return View(resetPassword); }

            if (string.IsNullOrEmpty(resetPassword.UserId) || string.IsNullOrEmpty(resetPassword.Token) || string.IsNullOrEmpty(resetPassword.NewPassword))
            { return RedirectToAction("Index"); }

            var user = await _userManager.FindByIdAsync(resetPassword.UserId);
            if (user == null) { return BadRequest(); }

            var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.NewPassword);
            if (!result.Succeeded) { return BadRequest(); }

            return RedirectToAction("ResetPasswordConfirmed");
        }

        public IActionResult ResetPasswordConfirmed() => View();
    }
}
