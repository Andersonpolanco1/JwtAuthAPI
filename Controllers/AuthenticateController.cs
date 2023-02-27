using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
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
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _conf;

        public AuthenticateController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration conf)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _conf = conf;
        }
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            if (_signInManager.IsSignedIn(User))
            {
                return Ok("Already signed in");
            }
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

        [Authorize]
        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return Ok();
        }

        private JwtSecurityToken GetToken(List<Claim> userClaims)
        {
            var authSinginKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_conf["JWT:Secret"]));
            var jwt = new JwtSecurityToken
                (
                    issuer: _conf["JWT:ValidIssuer"],
                    audience: _conf["JWT:ValidAudience"],
                    expires: DateTime.Now.AddMinutes(1),
                    claims: userClaims,
                    signingCredentials:new SigningCredentials(authSinginKey, SecurityAlgorithms.HmacSha256Signature)
                );

            return jwt;

        }
    }
}
