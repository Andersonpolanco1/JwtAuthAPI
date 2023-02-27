using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthAPI.Controllers
{
    [Authorize(UserRole.ADMIN)]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _conf;

        public UsersController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration conf)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _conf = conf;
        }

        [HttpGet]
        public async Task<IActionResult> GetUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            return Ok(users);
        }

        [HttpGet("id")]
        public async Task<IActionResult> GetUserById(string id)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Id == id);

            return user is null ?
                BadRequest(new Response { Status = "Error", Message = "USer not found" }) :
                Ok(user);
        }

    }
}
