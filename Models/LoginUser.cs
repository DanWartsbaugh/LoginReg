#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace LoginReg.Models;

[NotMapped]
public class LoginUser
{

    [Required(ErrorMessage = "is required")]
    [Display(Name = "Email address")]
    [EmailAddress]
    public string LoginEmail { get; set; }

    [Required(ErrorMessage = "is required")]
    [Display(Name = "Password")]
    [DataType(DataType.Password)]
    [MinLength(8, ErrorMessage ="Password must be at least 8 characters")]
    public string LoginPassword { get; set; }

}