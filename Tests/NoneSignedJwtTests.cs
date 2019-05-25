using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Tests
{
    public class NoneSignedJwtTests
    {
        [Fact]
        public void Can_Validate()
        {
            var write = new IdentityModelService();
            var read = new IdentityModelService();

            var payload = new Dictionary<string, string>
            {
                { "my_email", "alice@example.com" },
                { "admin", "true" }
            };

            var token = write.CreateToken(payload);

            var readPayload = read.ValidateToken(token);

            Assert.Equal(payload["my_email"], readPayload["my_email"]);
            Assert.Equal(payload["admin"], readPayload["admin"]);
        }

        public interface IJwtService
        {
            string CreateToken(Dictionary<string, string> payload);
            Dictionary<string, string> ValidateToken(string token);
        }

        public class IdentityModelService : IJwtService
        {
            public string CreateToken(Dictionary<string, string> payload)
            {
                var claims = payload.Select(kvp => new Claim(kvp.Key, kvp.Value));
                var subject = new ClaimsIdentity(claims);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = subject
                };

                var handler = new JwtSecurityTokenHandler
                {
                    SetDefaultTimesOnTokenCreation = false
                };

                var securityToken = handler.CreateToken(tokenDescriptor);
                return handler.WriteToken(securityToken);
            }

            public Dictionary<string, string> ValidateToken(string token)
            {
                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    RequireSignedTokens = false,
                    RequireExpirationTime = false
                };

                var handler = new JwtSecurityTokenHandler();

                var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);

                return principal.Claims.ToDictionary(c => c.Type, c => c.Value);
            }
        }

        public class ManualService : IJwtService
        {
            public string CreateToken(Dictionary<string, string> payload)
            {
                var header = new
                {
                    alg = "none"
                };
                var encodedHeader = Utils.ToBase64(Utils.ToJson(header));
                var encodedPayload = Utils.ToBase64(Utils.ToJson(payload));

                return $"{encodedHeader}.{encodedPayload}.";
            }

            public Dictionary<string, string> ValidateToken(string token)
            {
                var parts = token.Split('.');
                var encodedHeader = parts[0];
                var encodedPayload = parts[1];
                var encodedSignature = parts[2];

                var header = Utils.FromJson<dynamic>(Utils.FromBase64(encodedHeader));

                if (header.algo != "none")
                {
                    throw new Exception("Expected algo=none");
                }

                return Utils.FromJson<Dictionary<string, string>>(Utils.FromBase64(encodedPayload));
            }
        }
    }
}