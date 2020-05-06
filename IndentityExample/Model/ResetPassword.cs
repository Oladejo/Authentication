using System.ComponentModel.DataAnnotations;

namespace IndentityExample.Model
{
    public class ResetPassword
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Token { get; set; }

        [Required]
        public string NewPassword { get; set; }
    }
}
