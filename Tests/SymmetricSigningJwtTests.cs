using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Tests
{
    public class SymmetricSigningJwtTests
    {
        public static IEnumerable<object[]> Services
        {
            get
            {
                var services = new object[] { new IdentityModelService(), new ManualService() };
                foreach (var x in services)
                    foreach (var y in services)
                    {
                        yield return new[] { x, y };
                    }
            }
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Can_Verify(IJwtService writer, IJwtService reader)
        {
            writer.Secret = "TW9zaGVFcmV6UHJpdmF0ZUtleQ==";
            reader.Secret = writer.Secret;

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = writer.CreateToken(claims);

            var readPayload = reader.ValidateToken(token);

            Assert.Contains(readPayload, c => c.Type == "my_email" && c.Value == "alice@example.com");
            Assert.Contains(readPayload, c => c.Type == "admin" && c.Value == "true");
        }

        public interface IJwtService
        {
            string Secret { get; set; }
            string CreateToken(IEnumerable<Claim> claims);
            ICollection<Claim> ValidateToken(string token);
        }

        public class IdentityModelService : IJwtService
        {
            public string Secret { get; set; }

            public string CreateToken(IEnumerable<Claim> claims)
            {
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Convert.FromBase64String(Secret)), SecurityAlgorithms.HmacSha256Signature)
                };

                var handler = new JwtSecurityTokenHandler
                {
                    SetDefaultTimesOnTokenCreation = false
                };

                var securityToken = handler.CreateToken(tokenDescriptor);
                return handler.WriteToken(securityToken);
            }

            public ICollection<Claim> ValidateToken(string token)
            {
                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    RequireExpirationTime = false,
                    RequireSignedTokens = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(Secret))
                };

                var handler = new JwtSecurityTokenHandler();

                var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);

                return principal.Claims.ToList();
            }
        }

        public class ManualService : IJwtService
        {
            public string Secret { get; set; }

            public string CreateToken(IEnumerable<Claim> claims)
            {
                var header = new
                {
                    alg = "none"
                };
                var encodedHeader = Utils.ToBase64(Utils.ToJson(header));
                var encodedPayload = Utils.ToBase64(Utils.ToJson(claims.ToDictionary(c => c.Type, c => c.Value)));

                return $"{encodedHeader}.{encodedPayload}.";
            }

            public ICollection<Claim> ValidateToken(string token)
            {
                var parts = token.Split('.');
                var encodedHeader = parts[0];
                var encodedPayload = parts[1];
                var encodedSignature = parts[2];

                var header = Utils.FromJson<dynamic>(Utils.FromBase64(encodedHeader));


                if ((header.alg ?? "none") != "none")
                {
                    throw new Exception($"Expected alg=none, but got {header.alg}");
                }

                return Utils.FromJson<Dictionary<string, string>>(Utils.FromBase64(encodedPayload))
                    .Select(kvp => new Claim(kvp.Key, kvp.Value))
                    .ToList();
            }
        }
    }
}
