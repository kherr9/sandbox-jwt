using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Tests
{
    public class AudienceJwtTests
    {
        public static IEnumerable<object[]> Services
        {
            get
            {
                var services = new[] { typeof(IdentityModelService), typeof(ManualService) };
                foreach (var x in services)
                    foreach (var y in services)
                    {
                        yield return new[] { Activator.CreateInstance(x), Activator.CreateInstance(y) };
                    }
            }
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Can_Verify(IJwtService producer, IJwtService consumer)
        {
            producer.Secret = Utils.GenerateSecretAsString();
            consumer.Secret = producer.Secret;
            consumer.Audience = new[] { "alice" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims, new[] { "alice" });

            var readPayload = consumer.ValidateToken(token);

            Assert.Contains(readPayload, c => c.Type == "my_email" && c.Value == "alice@example.com");
            Assert.Contains(readPayload, c => c.Type == "admin" && c.Value == "true");
            Assert.Contains(readPayload, c => c.Type == "aud" && c.Value == "alice");
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Different_Audience(IJwtService producer, IJwtService consumer)
        {
            producer.Secret = Utils.GenerateSecretAsString();
            consumer.Secret = producer.Secret;
            consumer.Audience = new[] { "alice" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims, new[] { "bob" });

            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            Assert.Contains("Audience validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Audience_Required(IJwtService producer, IJwtService consumer)
        {
            producer.Secret = Utils.GenerateSecretAsString();
            consumer.Secret = producer.Secret;
            consumer.Audience = new[] { "alice" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims, new string[0]);

            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            Assert.Contains("Audience validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Token_Include_Multiple_Aud_Where_1_Matches(IJwtService producer, IJwtService consumer)
        {
            producer.Secret = Utils.GenerateSecretAsString();
            consumer.Secret = producer.Secret;
            consumer.Audience = new[] { "alice" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims, new[] { "alice", "bob" });

            var readPayload = consumer.ValidateToken(token);

            Assert.Contains(readPayload, c => c.Type == "my_email" && c.Value == "alice@example.com");
            Assert.Contains(readPayload, c => c.Type == "admin" && c.Value == "true");
            Assert.Contains(readPayload, c => c.Type == "aud" && c.Value == "alice");
            Assert.Contains(readPayload, c => c.Type == "aud" && c.Value == "bob");
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Token_Include_Multiple_Aud_Where_None_Matches(IJwtService producer, IJwtService consumer)
        {
            producer.Secret = Utils.GenerateSecretAsString();
            consumer.Secret = producer.Secret;
            consumer.Audience = new[] { "alice" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims, new[] { "bob", "charlie" });

            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            Assert.Contains("Audience validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Consumer_Has_Many_Audiences(IJwtService producer, IJwtService consumer)
        {
            producer.Secret = Utils.GenerateSecretAsString();
            consumer.Secret = producer.Secret;
            consumer.Audience = new[] { "alice", "bob" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims, new[] { "alice" });

            var readPayload = consumer.ValidateToken(token);

            Assert.Contains(readPayload, c => c.Type == "my_email" && c.Value == "alice@example.com");
            Assert.Contains(readPayload, c => c.Type == "admin" && c.Value == "true");
            Assert.Contains(readPayload, c => c.Type == "aud" && c.Value == "alice");
        }

        public interface IJwtService
        {
            string Secret { get; set; }
            string[] Audience { get; set; }
            string CreateToken(IEnumerable<Claim> claims, string[] audience);
            ICollection<Claim> ValidateToken(string token);
        }

        public class IdentityModelService : IJwtService
        {
            public string Secret { get; set; }

            public string[] Audience { get; set; }

            public string CreateToken(IEnumerable<Claim> claims, string[] audience)
            {
                claims = claims.Concat(audience.Select(a => new Claim("aud", a)));

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
                    ValidateAudience = true,
                    ValidAudiences = Audience,
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

            public string[] Audience { get; set; }

            public string CreateToken(IEnumerable<Claim> claims, string[] audience)
            {
                var header = new
                {
                    alg = "HS256",
                    typ = "JWT"
                };

                var payload = claims.ToDictionary(c => c.Type, c => (object)c.Value);

                switch (audience.Length)
                {
                    case 0:
                        break;
                    case 1:
                        payload["aud"] = audience.Single();
                        break;
                    default:
                        payload["aud"] = audience;
                        break;
                }

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

                if (string.IsNullOrEmpty(encodedSignature))
                {
                    throw new Exception("Unable to validate signature, token does not have a signature");
                }

                var computedSignature = Utils.ToBase64(Hmac($"{encodedHeader}.{encodedPayload}"));
                if (!string.Equals(computedSignature, encodedSignature))
                {
                    throw new Exception("Signature validation failed");
                }

                var payloadDict = Utils.FromJson<Dictionary<string, object>>(Utils.FromBase64(encodedPayload));

                var payload = new List<Claim>();
                foreach (var kvp in payloadDict)
                {
                    switch (kvp.Value)
                    {
                        case string stringValue:
                            payload.Add(new Claim(kvp.Key, stringValue));
                            break;
                        case JArray stringsValue:
                            payload.AddRange(stringsValue.Select(x => new Claim(kvp.Key, x.Value<string>())));
                            break;
                        default:
                            throw new Exception($"I don't know how to handle {kvp.Value.GetType().Name}");

                    }
                }

                if (!payload.Any(c => c.Type == "aud" && Audience.Contains(c.Value)))
                {
                    throw new Exception("Audience validation failed");
                }

                return payload;
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
