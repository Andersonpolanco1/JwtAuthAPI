using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
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

        private JwtSecurityToken GetToken(List<Claim> userClaims)
        {
            var authSinginKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_conf["JWT:Secret"]));
            return new JwtSecurityToken
                (
                    issuer: _conf["JWT:ValidIssuer"],
                    audience: _conf["JWT:ValidAudience"],
                    expires: DateTime.Now.AddMinutes(1),
                    claims: userClaims,
                    signingCredentials:new SigningCredentials(authSinginKey, SecurityAlgorithms.Sha256)
                );
        }
    }
}
