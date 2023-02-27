using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.WebSockets;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;

namespace JwtAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _conf;

        public AuthenticateController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration conf)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _conf = conf;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            var user = await _userManager.FindByNameAsync(login.Username);

            if (user is null) 
                return Unauthorized("User not found.");

            var successLogin = await  _userManager.CheckPasswordAsync(user, login.Password);

            if (!successLogin) 
                return Unauthorized("Login failed.");

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = GetToken(authClaims);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }

        [HttpPost("Register")]
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

        [HttpGet("id")]
        public async Task<IActionResult> GetUserById(string id)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Id == id);

            return user is null ? 
                BadRequest(new Response { Status = "Error", Message = "USer not found" }) : 
                Ok(user);
        }



        private JwtSecurityToken GetToken(List<Claim> userClaims)
        {
            var authSinginKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_conf["JWT:Secret"]));
            return new JwtSecurityToken
                (
                    issuer: _conf["JWT:ValidIssuer"],
                    audience: _conf["JWT:ValidAudience"],
                    expires: DateTime.Now.AddMinutes(1),
                    claims: userClaims,
                    signingCredentials:new SigningCredentials(authSinginKey, SecurityAlgorithms.HmacSha256Signature)
                );
        }
    }
}
