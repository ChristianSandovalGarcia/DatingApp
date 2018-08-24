
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository authRepo, IConfiguration config)
        {
            this._config = config;
            this._authRepo = authRepo;

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegistrationDto user)
        {
            user.Username = user.Username.ToLower();
            if (await _authRepo.UserExists(user.Username))
                return BadRequest("Username already exists");

            var userToCreate = new UserModel
            {
                Username = user.Username
            };

            var createdUser = await _authRepo.Register(userToCreate, user.Password);
            return StatusCode(201);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto user)
        {
            var userFromRepo = await _authRepo.Login(user.Username.ToLower(), user.Password);
            if (userFromRepo == null) return Unauthorized();

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));
            
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddHours(10),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);
    
            return Ok(new {
                token = tokenHandler.WriteToken(token)
            });
        }
    }
}