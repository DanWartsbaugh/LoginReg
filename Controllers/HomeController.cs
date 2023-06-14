using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Filters;
using LoginReg.Models;

namespace LoginReg.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private MyContext _context;

    public HomeController(ILogger<HomeController> logger, MyContext context)
    {
        _logger = logger;

        _context = context;
    }

    public IActionResult Index()
    {
        return View("Index");
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

    [SessionCheck]
    [HttpGet("success")]
    public IActionResult Success()
    {
        return View("Success");
    }

    //Post route for registration (redirect to success page)
    [HttpPost("register")]
    public IActionResult Register(User newUser)
    {
        if (!ModelState.IsValid)
        {
            return Index();
        }

        PasswordHasher<User> hashedpwd = new PasswordHasher<User>();
        newUser.Password = hashedpwd.HashPassword(newUser, newUser.Password);
        //add to db
        _context.Users.Add(newUser);
        _context.SaveChanges();

        //log in (add to session)
        HttpContext.Session.SetInt32("UUID", newUser.UserId);
        return RedirectToAction("Success");
    }

    //Post route for LogIn (redirect to success page)
    [HttpPost("login")]
    public IActionResult Login(LoginUser loginUser)
    {
        if (!ModelState.IsValid)
        {
            return Index();
        }

        User? dbUser = _context.Users.FirstOrDefault(u => u.Email == loginUser.LoginEmail);

        if (dbUser == null)
        {
            ModelState.AddModelError("Email", "not a valid email/password combo");
            return Index();
        }

        PasswordHasher<LoginUser> hashedpwd = new PasswordHasher<LoginUser>();
        PasswordVerificationResult pwCompareResult = hashedpwd.VerifyHashedPassword(loginUser, dbUser.Password, loginUser.LoginPassword);

        if (pwCompareResult == 0)
        {
            ModelState.AddModelError("Password", "not a valid email/password combo");
            return Index();
        }

        HttpContext.Session.SetInt32("UUID", dbUser.UserId);
        return RedirectToAction("Success");
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }
}

// Name this anything you want with the word "Attribute" at the end
public class SessionCheckAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        // Find the session, but remember it may be null so we need int?
        int? userId = context.HttpContext.Session.GetInt32("UUID");
        // Check to see if we got back null
        if(userId == null)
        {
            // Redirect to the Index page if there was nothing in session
            // "Home" here is referring to "HomeController", you can use any controller that is appropriate here
            context.Result = new RedirectToActionResult("Index", "Home", null);
        }
    }
}

