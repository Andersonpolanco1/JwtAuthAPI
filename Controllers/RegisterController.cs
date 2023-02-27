using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthAPI.Controllers
{
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class RegisterController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;

        public RegisterController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] Register register)
        {
            var userExists = await _userManager.Users.AnyAsync(u => u.UserName == register.Username);

            if (userExists)
                return BadRequest(new Response { Status = "Error", Message = "User already exists" });

            var newUser = new IdentityUser()
            {
                UserName = register.Username,
                Email = register.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(newUser, register.Password);

            if (result.Succeeded)
                return CreatedAtAction("GetUserById", new { id = newUser.Id }, newUser);

            var error = result.Errors.FirstOrDefault();
            var errorMessage = error is null ? "User can not be registered" : error.Description;

            return BadRequest(new Response { Status = "Error", Message = errorMessage });
        }
    }
}
