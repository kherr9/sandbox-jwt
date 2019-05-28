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
    public class FullJwtTests
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
            producer.PrivateKeyPem = Utils.Rsa.PrivateKey;

            consumer.PublicKeyPem = Utils.Rsa.PublicKey;
            consumer.Audiences = new[] { "https://consumer.com" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true"),
                new Claim("aud", "https://consumer.com")
            };

            var token = producer.CreateToken(claims);

            var readPayload = consumer.ValidateToken(token);

            Assert.Contains(readPayload, c => c.Type == "my_email" && c.Value == "alice@example.com");
            Assert.Contains(readPayload, c => c.Type == "admin" && c.Value == "true");
            Assert.Contains(readPayload, c => c.Type == "aud" && c.Value == "https://consumer.com");
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Different_Public_Key_Fails(IJwtService producer, IJwtService consumer)
        {
            producer.PrivateKeyPem = Utils.Rsa.PrivateKey;

            consumer.PublicKeyPem = Utils.Rsa.OtherPublicKey;
            consumer.Audiences = new[] { "https://consumer.com" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims);

            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            Assert.Contains("Signature validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Unknown_Audience(IJwtService producer, IJwtService consumer)
        {
            producer.PrivateKeyPem = Utils.Rsa.PrivateKey;

            consumer.PublicKeyPem = Utils.Rsa.PublicKey;
            consumer.Audiences = new[] { "https://consumer.com" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true"),
                new Claim("aud", "https://acme.com")
            };

            var token = producer.CreateToken(claims);

            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            Assert.Contains("Audience validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Required_Audience(IJwtService producer, IJwtService consumer)
        {
            producer.PrivateKeyPem = Utils.Rsa.PrivateKey;

            consumer.PublicKeyPem = Utils.Rsa.PublicKey;
            consumer.Audiences = new[] { "https://consumer.com" };

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims);

            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            Assert.Contains("Audience validation failed", ex.Message);
        }

        public interface IJwtService
        {
            string PrivateKeyPem { get; set; }
            string PublicKeyPem { get; set; }
            string[] Audiences { get; set; }
            string CreateToken(IEnumerable<Claim> claims);
            ICollection<Claim> ValidateToken(string token);
        }

        public class IdentityModelService : IJwtService
        {
            public string PrivateKeyPem { get; set; }

            public string PublicKeyPem { get; set; }

            public string[] Audiences { get; set; }

            public string CreateToken(IEnumerable<Claim> claims)
            {
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(Utils.Rsa.PrivateKeyFromPem(PrivateKeyPem),
                        SecurityAlgorithms.RsaSha256Signature)
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
                    ValidAudiences = Audiences,
                    RequireExpirationTime = false,
                    RequireSignedTokens = true,
                    IssuerSigningKey = Utils.Rsa.PublicKeyFromPem(PublicKeyPem)
                };

                var handler = new JwtSecurityTokenHandler();

                var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);

                return principal.Claims.ToList();
            }
        }

        public class ManualService : IJwtService
        {
            public string PrivateKeyPem { get; set; }

            public string PublicKeyPem { get; set; }

            public string[] Audiences { get; set; }

            public string CreateToken(IEnumerable<Claim> claims)
            {
                var header = new
                {
                    alg = "RS256",
                    typ = "JWT"
                };

                var payload = Utils.ConvertToDictionary(claims);

                var headerJson = Json(header);
                var payloadJson = Json(payload);

                var head = $"{Base64(headerJson)}.{Base64(payloadJson)}";

                var encodedSignature = Base64(Sign(GetBytes(head), PrivateKeyPem));

                return $"{head}.{encodedSignature}";
            }

            public ICollection<Claim> ValidateToken(string token)
            {
                var parts = token.Split('.');
                var encodedHeader = parts[0];
                var encodedPayload = parts[1];
                var encodedSignature = parts[2];

                var header = FromJson<dynamic>(FromBase64AsString(encodedHeader));

                if (header.alg != "RS256")
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

                var head = $"{encodedHeader}.{encodedPayload}";

                if (!Verify(GetBytes(head), FromBase64AsBytes(encodedSignature), PublicKeyPem))
                {
                    throw new Exception("Signature validation failed");
                }

                var payload = Utils.ParseClaims(FromBase64AsString(encodedPayload));

                if (!payload.Any(c => c.Type == "aud" && Audiences.Contains(c.Value)))
                {
                    throw new Exception("Audience validation failed");
                }

                return payload;
            }

            private static string Json(object value) => Utils.ToJson(value);
            private static T FromJson<T>(string json) => Utils.FromJson<T>(json);
            private static string Base64(byte[] data) => Utils.ToBase64(data);
            private static string Base64(string data) => Utils.ToBase64(data);
            private static byte[] FromBase64AsBytes(string data) => Utils.FromBase64ToBytes(data);
            private static string FromBase64AsString(string data) => Utils.FromBase64(data);
            public static byte[] GetBytes(string data) => Encoding.UTF8.GetBytes(data);
            private static byte[] Sign(byte[] data, string privateKey) => RsaSign(data, Utils.Rsa.PrivateKeyFromPem(privateKey));
            private static bool Verify(byte[] data, byte[] signature, string publicKey) => VerifySignature(data, signature, Utils.Rsa.PublicKeyFromPem(publicKey));

            private static byte[] RsaSign(byte[] data, RsaSecurityKey key)
            {
                using (var rsa = RSA.Create(key.Parameters))
                {
                    return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }

            private static bool VerifySignature(byte[] data, byte[] signature, RsaSecurityKey key)
            {
                using (var rsa = RSA.Create(key.Parameters))
                {
                    return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
        }
    }
}
