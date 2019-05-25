using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Domain.Managers
{
    public class JwtAuthService
    {
        public string SecretKey { get; set; } = "TW9zaGVFcmV6UHJpdmF0ZUtleQ==";

        public bool IsTokenValid(string token)
        {
            var tokenValidationParameters = GetTokenValidationParameters();

            var handler = new JwtSecurityTokenHandler();

            try
            {
                var tokenValid = handler.ValidateToken(token, tokenValidationParameters, out var _);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public string GenerateToken(JwtContainerModel model)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(model.Claims),
                Expires = DateTime.UtcNow.AddMinutes(model.ExpiresMinutes),
                SigningCredentials = new SigningCredentials(GetSymmetricSecurityKey(), model.SecretAlgorithm)
            };

            var handler = new JwtSecurityTokenHandler();
            var securityToken = handler.CreateToken(tokenDescriptor);
            var token = handler.WriteToken(securityToken);

            return token;
        }

        public ClaimsPrincipal ValidateToken(string token, out SecurityToken validatedToken)
        {
            var tokenValidationParameters = GetTokenValidationParameters();

            var handler = new JwtSecurityTokenHandler();

            return handler.ValidateToken(token, tokenValidationParameters, out validatedToken);
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = GetSymmetricSecurityKey()
            };
        }

        private SecurityKey GetSymmetricSecurityKey()
        {
            var key = Convert.FromBase64String(SecretKey);
            return new SymmetricSecurityKey(key);
        }
    }

    public class JwtContainerModel
    {
        public string SecretAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256Signature;
        public int ExpiresMinutes { get; set; } = 10080; // 7 days
        public Claim[] Claims { get; set; }
    }
}
