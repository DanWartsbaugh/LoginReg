#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace LoginReg.Models;
public class User
{
    [Key]
    [Required]
    public int UserId { get; set; }

    [Required(ErrorMessage = "is required")]
    [MinLength(2, ErrorMessage = "must be at least 2 characters")]
    [Display(Name = "First Name")]
    public string FirstName { get; set; }

    [Required(ErrorMessage = "is required")]
    [MinLength(2, ErrorMessage = "must be at least 2 characters")]
    [Display(Name = "Last Name")]
    public string LastName { get; set; }

    [Required(ErrorMessage = "is required")]
    [EmailAddress]
    [UniqueEmail]
    public string Email { get; set; }

    [Required(ErrorMessage = "is required")]
    [DataType(DataType.Password)]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
    public string Password { get; set; }

    [NotMapped]
    [Compare("Password")]
    [DataType(DataType.Password)]
    [Display(Name = "PW Confirm")]
    public string PasswordConfirm { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime UpdatedAt { get; set; } = DateTime.Now;
}

//Verify that the email address being registered is not already in database
public class UniqueEmailAttribute : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value == null)
        {
            return new ValidationResult("Email is required!");
        }

        MyContext _context = (MyContext)validationContext.GetService(typeof(MyContext));
        // Check to see if there are any records of this email in our database
        if (_context.Users.Any(e => e.Email == value.ToString()))
        {
            // If yes, throw an error
            return new ValidationResult("Email must be unique!");
        }
        else
        {
            // If no, proceed
            return ValidationResult.Success;
        }
    }
}

