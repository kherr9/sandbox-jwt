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
    public class RsaSigningJwtTests
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

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims);

            var readPayload = consumer.ValidateToken(token);

            Assert.Contains(readPayload, c => c.Type == "my_email" && c.Value == "alice@example.com");
            Assert.Contains(readPayload, c => c.Type == "admin" && c.Value == "true");
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Different_Public_Key_Fails(IJwtService producer, IJwtService consumer)
        {
            producer.PrivateKeyPem = Utils.Rsa.PrivateKey;
            consumer.PublicKeyPem = Utils.Rsa.OtherPublicKey;

            var claims = new[]
            {
                new Claim("my_email", "alice@example.com"),
                new Claim("admin", "true")
            };

            var token = producer.CreateToken(claims);

            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            Assert.Contains("Signature validation failed", ex.Message);
        }

        public interface IJwtService
        {
            string PrivateKeyPem { get; set; }
            string PublicKeyPem { get; set; }
            string CreateToken(IEnumerable<Claim> claims);
            ICollection<Claim> ValidateToken(string token);
        }

        public class IdentityModelService : IJwtService
        {
            public string PrivateKeyPem { get; set; }

            public string PublicKeyPem { get; set; }

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
                    ValidateAudience = false,
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

            public string CreateToken(IEnumerable<Claim> claims)
            {
                var header = new
                {
                    alg = "RS256",
                    typ = "JWT"
                };
                var payload = claims.ToDictionary(c => c.Type, c => c.Value);

                var encodedHeader = Utils.ToBase64(Utils.ToJson(header));
                var encodedPayload = Utils.ToBase64(Utils.ToJson(payload));

                var head = $"{encodedHeader}.{encodedPayload}";

                var encodedSignature = Utils.ToBase64(RsaSign(head, Utils.Rsa.PrivateKeyFromPem(PrivateKeyPem)));

                return $"{head}.{encodedSignature}";
            }

            public ICollection<Claim> ValidateToken(string token)
            {
                var parts = token.Split('.');
                var encodedHeader = parts[0];
                var encodedPayload = parts[1];
                var encodedSignature = parts[2];

                var header = Utils.FromJson<dynamic>(Utils.FromBase64(encodedHeader));

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

                if (!VerifySignature(
                    data: Encoding.UTF8.GetBytes(head),
                    signature: Encoding.UTF8.GetBytes(Utils.FromBase64(encodedSignature)),
                    key: Utils.Rsa.PublicKeyFromPem(PublicKeyPem)))
                {
                    throw new Exception("Signature validation failed");
                }

                return Utils.FromJson<Dictionary<string, string>>(Utils.FromBase64(encodedPayload))
                    .Select(kvp => new Claim(kvp.Key, kvp.Value))
                    .ToList();
            }

            private byte[] RsaSign(string head, RsaSecurityKey key)
            {
                using (var rsa = RSA.Create(key.Parameters))
                {
                    return rsa.SignData(Encoding.UTF8.GetBytes(head), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }

            private bool VerifySignature(byte[] data, byte[] signature, RsaSecurityKey key)
            {
                using (var rsa = RSA.Create(key.Parameters))
                {
                    return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
        }
    }
}
