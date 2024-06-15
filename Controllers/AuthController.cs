using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using JWT.Extensions;
using JWT.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers;

[ApiController]
[Route("auth")]
public class AuthController(IConfiguration config, IUserService userService) : ControllerBase
{
    
    [HttpPost("login")]
    public IActionResult Login(LoginRequestModel model)
    {
        try
        {
            var user = userService.GetUser(model.UserName);
            var passwordHasher = new PasswordHasher<User>();
            var isPasswordCorrect = passwordHasher.VerifyHashedPassword(new User(), user.HashedPassword, model.Password) ==
                                    PasswordVerificationResult.Success;
            if (!isPasswordCorrect)
                return Unauthorized("Wrong username or password");
        }
        catch (NotFoundException e)
        {
            return Unauthorized("User doesn't exist");
        }
        
        


        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescription = new SecurityTokenDescriptor
        {
            Issuer = config["JWT:Issuer"],
            Audience = config["JWT:Audience"],
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Key"]!)),
                SecurityAlgorithms.HmacSha256
            )
        };
        var token = tokenHandler.CreateToken(tokenDescription);
        var stringToken = tokenHandler.WriteToken(token);

        var refTokenDescription = new SecurityTokenDescriptor
        {
            Issuer = config["JWT:RefIssuer"],
            Audience = config["JWT:RefAudience"],
            Expires = DateTime.UtcNow.AddDays(3),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:RefKey"]!)),
                SecurityAlgorithms.HmacSha256
            )
        };
        var refToken = tokenHandler.CreateToken(refTokenDescription);
        var stringRefToken = tokenHandler.WriteToken(refToken);

        return Ok(new LoginResponseModel
        {
            Token = stringToken,
            RefreshToken = stringRefToken
        });
    }

    [HttpPost("refresh")]
    public IActionResult RefreshToken(RefreshTokenRequestModel requestModel)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            tokenHandler.ValidateToken(requestModel.RefreshToken, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = config["JWT:RefIssuer"],
                ValidAudience = config["JWT:RefAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:RefKey"]!))
            }, out SecurityToken validatedToken);

            var tokenDescription = new SecurityTokenDescriptor
            {
                Issuer = config["JWT:Issuer"],
                Audience = config["JWT:Audience"],
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Key"]!)),
                    SecurityAlgorithms.HmacSha256
                )
            };
            var token = tokenHandler.CreateToken(tokenDescription);
            var stringToken = tokenHandler.WriteToken(token);

            var refTokenDescription = new SecurityTokenDescriptor
            {
                Issuer = config["JWT:RefIssuer"],
                Audience = config["JWT:RefAudience"],
                Expires = DateTime.UtcNow.AddDays(3),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:RefKey"]!)),
                    SecurityAlgorithms.HmacSha256
                )
            };
            var refToken = tokenHandler.CreateToken(refTokenDescription);
            var stringRefToken = tokenHandler.WriteToken(refToken);

            return Ok(new LoginResponseModel
            {
                Token = stringToken,
                RefreshToken = stringRefToken
            });
        }
        catch
        {
            return Unauthorized();
        }
    }

    [HttpPost("register")]
    public IActionResult Register(LoginRequestModel requestModel)
    {
        if (userService.DoesUserExist(requestModel.UserName))
        {
            return Conflict(new { message = "Username already exists" });
        }
        var passwordHasher = new PasswordHasher<User>();
        var hashedPassword = passwordHasher.HashPassword(new User(), requestModel.Password);
        userService.AddUser(new UserInDatabase
        {
            Login = requestModel.UserName,
            HashedPassword = hashedPassword
        });
        
        return NoContent();
    }

    public class LoginRequestModel
    {
        [Required] public string UserName { get; set; } = null!;
        [Required] public string Password { get; set; } = null!;
    }

    public class LoginResponseModel
    {
        public string Token { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
    }

    public class User
    {
        public string Name { get; set; } = null!;
        public string Password { get; set; } = null!;
    }

    public class UserInDatabase
    {
        public string Login { get; set; } = null!;
        public string HashedPassword { get; set; } = null!;
    }
    
    public class RefreshTokenRequestModel
    {
        public string RefreshToken { get; set; } = null!;
    }

    
}