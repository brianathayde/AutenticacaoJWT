using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AutenticacaoJWT.Database;
using AutenticacaoJWT.Services;
using AutenticacaoJWT.DTOs;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;

namespace AthaydeIam.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authservice;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthController(AuthService authservice, UserManager<User> userManager,
            SignInManager<User> signInManager,
            IConfiguration configuration)
        {
            _authservice = authservice;
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO model)
        {
            EmailAddressAttribute _emailAddressAttribute = new();
            if (string.IsNullOrEmpty(model.Email) || !_emailAddressAttribute.IsValid(model.Email))
            {
                return BadRequest(new { error = "Invalid email" });
            }
            var user = new User { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok(new { result = "User created successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO model)
        {
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var token = await _authservice.GetAccessToken(user);
                var refreshToken = _authservice.GetRefreshToken();
                user.RefreshToken = refreshToken;
                int.TryParse(_configuration["Jwt:RefreshTokenExpiryTime"], out int RefreshTokenExpiryTime);
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(RefreshTokenExpiryTime);
                await _userManager.UpdateAsync(user);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    refreshToken,
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenDTO tokenModel)
        {
            if (tokenModel is null)
            {
                return BadRequest("Invalid client request");
            }

            string? accessToken = tokenModel.AccessToken ?? throw new ArgumentNullException(nameof(tokenModel));
            var principal = _authservice.GetDataFromExpiredToken(accessToken!);
            if (principal == null)
            {
                return BadRequest("Invalid access token/refresh token");
            }

            string username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username!);
            string? refreshToken = tokenModel.RefreshToken ?? throw new ArgumentException(nameof(tokenModel));
            if (user == null || user.RefreshToken != refreshToken
                || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token/refresh token");
            }

            var newRefreshToken = _authservice.GetRefreshToken();
            user.RefreshToken = newRefreshToken;
            int.TryParse(_configuration["Jwt:RefreshTokenExpiryTime"], out int RefreshTokenExpiryTime);
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(RefreshTokenExpiryTime);
            await _userManager.UpdateAsync(user);
            var newAccessToken = await _authservice.GetAccessTokenFromClaims(principal.Claims.ToList());
            return new ObjectResult(new
            {
                accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken
            });
        }


        [HttpGet("check-access")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> CheckAccess()
        {
            return Ok();
        }

        [HttpPost("change-password")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDTO model)
        {
            if (model == null)
            {
                return BadRequest(new { message = "Invalid request" });
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return NotFound(new { message = "User not found" });
            }

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new { result = "Password changed successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("revoke")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> RevokeRefreshToken(string accessToken)
        {
            var principal = _authservice.GetDataFromExpiredToken(accessToken);
            if (principal == null || principal.Identity == null 
                || principal.Identity.Name == null)
            {
                return BadRequest("Invalid access token");
            }
            var user = await _userManager.FindByNameAsync(principal.Identity.Name);
            if (user == null)
            {
                return BadRequest("Invalid user name");
            }
            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);
            return NoContent();
        }
    }
}
