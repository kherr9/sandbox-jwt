using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
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

        [Theory]
        [MemberData(nameof(Services))]
        public void Tamper_Payload(IJwtService writer, IJwtService reader)
        {
            writer.Secret = "TW9zaGVFcmV6UHJpdmF0ZUtleQ==";
            reader.Secret = writer.Secret;

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "false")
            };

            var token = writer.CreateToken(claims);

            var parts = token.Split('.');
            var payload = Utils.FromJson<JObject>(Utils.FromBase64(parts[1]));
            payload["admin"] = "true";
            parts[1] = Utils.ToBase64(Utils.ToJson(payload));

            var tamperedToken = $"{parts[0]}.{parts[1]}.{parts[2]}";

            var ex = Assert.ThrowsAny<Exception>(() => reader.ValidateToken(tamperedToken));

            Assert.Contains("Signature validation failed", ex.Message);
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
                    alg = "HS256",
                    typ = "JWT"
                };
                var payload = claims.ToDictionary(c => c.Type, c => c.Value);

                var encodedHeader = Utils.ToBase64(Utils.ToJson(header));
                var encodedPayload = Utils.ToBase64(Utils.ToJson(payload));

                var head = $"{encodedHeader}.{encodedPayload}";

                var encodedSignature = Utils.ToBase64(Hmac(head));

                return $"{head}.{encodedSignature}";
            }

            public ICollection<Claim> ValidateToken(string token)
            {
                var parts = token.Split('.');
                var encodedHeader = parts[0];
                var encodedPayload = parts[1];
                var encodedSignature = parts[2];

                var header = Utils.FromJson<dynamic>(Utils.FromBase64(encodedHeader));

                if (header.alg != "HS256")
                {
                    throw new Exception($"Expected alg=HS256, but got {header.alg}");
                }

                if (header.typ != "JWT")
                {
                    throw new Exception($"Expected typ=JWT, but got {header.typ}");
                }

                var computedSignature = Utils.ToBase64(Hmac($"{encodedHeader}.{encodedPayload}"));
                if (!string.Equals(computedSignature, encodedSignature))
                {
                    throw new Exception("Signature validation failed");
                }

                return Utils.FromJson<Dictionary<string, string>>(Utils.FromBase64(encodedPayload))
                    .Select(kvp => new Claim(kvp.Key, kvp.Value))
                    .ToList();
            }

            private byte[] Hmac(string plainText)
            {
                using (var hmac = new HMACSHA256(Convert.FromBase64String(Secret)))
                {
                    return hmac.ComputeHash(Encoding.UTF8.GetBytes(plainText));
                }
            }
        }
    }
}
