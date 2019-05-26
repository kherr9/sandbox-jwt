using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Tests
{
    public class KeyRotationJwtTests
    {
        public static IEnumerable<object[]> Services
        {
            get
            {
                var services = new [] { typeof(IdentityModelService), typeof(ManualService) };
                foreach (var x in services)
                    foreach (var y in services)
                    {
                        yield return new[] { Activator.CreateInstance(x), Activator.CreateInstance(y) };
                    }
            }
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Can_Verify(IJwtService writer, IJwtService reader)
        {
            var keys = new Dictionary<string, string>()
            {
                { "1", Utils.GenerateSecretAsString() },
                { "2", Utils.GenerateSecretAsString() }
            };

            writer.Secrets = keys;
            reader.Secrets = keys;

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            foreach (var keyId in new[] { "1", "2" })
            {
                var token = writer.CreateToken(claims, keyId);

                var readPayload1 = reader.ValidateToken(token);

                Assert.Contains(readPayload1, c => c.Type == "my_email" && c.Value == "alice@example.com");
                Assert.Contains(readPayload1, c => c.Type == "admin" && c.Value == "true");
            }
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Unknown_Kid(IJwtService writer, IJwtService reader)
        {
            writer.Secrets = new Dictionary<string, string>()
            {
                { "1", Utils.GenerateSecretAsString() }
            };
            reader.Secrets = new Dictionary<string, string>()
            {
                { "2", Utils.GenerateSecretAsString() }
            };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = writer.CreateToken(claims, "1");

            var ex = Assert.ThrowsAny<Exception>(() => reader.ValidateToken(token));

            Assert.Contains("Signature validation failed. Unable to match keys", ex.Message);
        }

        public interface IJwtService
        {
            Dictionary<string, string> Secrets { get; set; }
            string CreateToken(IEnumerable<Claim> claims, string kid);
            ICollection<Claim> ValidateToken(string token);
        }

        public class IdentityModelService : IJwtService
        {
            public Dictionary<string, string> Secrets { get; set; }

            public string CreateToken(IEnumerable<Claim> claims, string kid)
            {
                var key = new SymmetricSecurityKey(Convert.FromBase64String(Secrets[kid]))
                {
                    KeyId = kid
                };

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
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
                var keys = Secrets
                    .Select(kvp => new SymmetricSecurityKey(Convert.FromBase64String(kvp.Value)) { KeyId = kvp.Key })
                    .ToList();

                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    RequireExpirationTime = false,
                    RequireSignedTokens = true,
                    IssuerSigningKeys = keys
                };

                var handler = new JwtSecurityTokenHandler();

                var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);

                return principal.Claims.ToList();
            }
        }

        public class ManualService : IJwtService
        {
            public Dictionary<string, string> Secrets { get; set; }

            public string CreateToken(IEnumerable<Claim> claims, string kid)
            {
                var header = new
                {
                    alg = "HS256",
                    typ = "JWT",
                    kid = kid
                };
                var payload = claims.ToDictionary(c => c.Type, c => c.Value);

                var encodedHeader = Utils.ToBase64(Utils.ToJson(header));
                var encodedPayload = Utils.ToBase64(Utils.ToJson(payload));

                var head = $"{encodedHeader}.{encodedPayload}";

                var encodedSignature = Utils.ToBase64(Hmac(head, Secrets[kid]));

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

                if (header.kid == null)
                {
                    throw new Exception("Must specify kid");
                }

                if (!Secrets.TryGetValue((string) header.kid, out var secret))
                {
                    throw new Exception("Signature validation failed. Unable to match keys");
                }

                if (string.IsNullOrEmpty(encodedSignature))
                {
                    throw new Exception("Unable to validate signature, token does not have a signature");
                }

                var computedSignature = Utils.ToBase64(Hmac($"{encodedHeader}.{encodedPayload}", secret));
                if (!string.Equals(computedSignature, encodedSignature))
                {
                    throw new Exception("Signature validation failed");
                }

                return Utils.FromJson<Dictionary<string, string>>(Utils.FromBase64(encodedPayload))
                    .Select(kvp => new Claim(kvp.Key, kvp.Value))
                    .ToList();
            }

            private byte[] Hmac(string plainText, string secret)
            {
                using (var hmac = new HMACSHA256(Convert.FromBase64String(secret)))
                {
                    return hmac.ComputeHash(Encoding.UTF8.GetBytes(plainText));
                }
            }
        }
    }
}
