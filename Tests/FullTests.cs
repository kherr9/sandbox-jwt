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
                        var producer = (IJwtService)Activator.CreateInstance(x);
                        producer.PrivateKey = new KeyValuePair<string, string>("key_001", Utils.Rsa.PrivateKey);

                        var consumer = (IJwtService)Activator.CreateInstance(y);
                        consumer.PublicKeys = new Dictionary<string, string>()
                        {
                            { "key_001", Utils.Rsa.PublicKey }
                        };
                        consumer.Audiences = new[] { "https://consumer.com" };
                        consumer.Issuers = new[] { "https://producer.com" };

                        var claims = new List<Claim>
                        {
                            new Claim("my_email", "alice@example.com"),
                            new Claim("admin", "false"),
                            new Claim("iss", "https://producer.com"),
                            new Claim("aud", "https://consumer.com")
                        };

                        yield return new object[] { producer, consumer, claims };
                    }
            }
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Can_Verify(IJwtService producer, IJwtService consumer, List<Claim> claims)
        {
            // Act
            var token = producer.CreateToken(claims);
            var readPayload = consumer.ValidateToken(token);

            // Assert
            Assert.Contains(readPayload, c => c.Type == "my_email" && c.Value == "alice@example.com");
            Assert.Contains(readPayload, c => c.Type == "admin" && c.Value == "false");
            Assert.Contains(readPayload, c => c.Type == "iss" && c.Value == "https://producer.com");
            Assert.Contains(readPayload, c => c.Type == "aud" && c.Value == "https://consumer.com");
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Different_Public_Key_Fails(IJwtService producer, IJwtService consumer, List<Claim> claims)
        {
            // Arrange
            consumer.PublicKeys["key_001"] = Utils.Rsa.OtherPublicKey;

            // Act
            var token = producer.CreateToken(claims);
            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            // Assert
            Assert.Contains("Signature validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void PublicKey_NotFound(IJwtService producer, IJwtService consumer, List<Claim> claims)
        {
            // Arrange
            consumer.PublicKeys.Clear();
            consumer.PublicKeys["key_002"] = Utils.Rsa.PublicKey;

            // Act
            var token = producer.CreateToken(claims);
            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            // Assert
            Assert.Contains("Signature validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Audience_NotFound(IJwtService producer, IJwtService consumer, List<Claim> claims)
        {
            // Arrange
            claims.RemoveAll(c => c.Type == "aud");
            claims.Add(new Claim("aud", "https://acme.com"));

            // Act
            var token = producer.CreateToken(claims);
            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            // Assert
            Assert.Contains("Audience validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Audience_Required(IJwtService producer, IJwtService consumer, List<Claim> claims)
        {
            // Arrange
            claims.RemoveAll(c => c.Type == "aud");

            // Act
            var token = producer.CreateToken(claims);
            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            // Assert
            Assert.Contains("Audience validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Issuer_NotFound(IJwtService producer, IJwtService consumer, List<Claim> claims)
        {
            // Arrange
            claims.RemoveAll(c => c.Type == "iss");
            claims.Add(new Claim("iss", "https://acme.com"));

            // Act
            var token = producer.CreateToken(claims);
            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            // Assert
            Assert.Contains("Issuer validation failed", ex.Message);
        }

        [Theory]
        [MemberData(nameof(Services))]
        public void Issuer_Required(IJwtService producer, IJwtService consumer, List<Claim> claims)
        {
            // Arrange
            claims.RemoveAll(c => c.Type == "iss");

            // Act
            var token = producer.CreateToken(claims);
            var ex = Assert.ThrowsAny<Exception>(() => consumer.ValidateToken(token));

            // Assert
            Assert.Contains("Unable to validate issuer", ex.Message);
        }

        public interface IJwtService
        {
            KeyValuePair<string, string> PrivateKey { get; set; }
            Dictionary<string, string> PublicKeys { get; set; }
            string[] Audiences { get; set; }
            string[] Issuers { get; set; }
            string CreateToken(IEnumerable<Claim> claims);
            ICollection<Claim> ValidateToken(string token);
        }

        public class IdentityModelService : IJwtService
        {
            public KeyValuePair<string, string> PrivateKey { get; set; }

            public Dictionary<string, string> PublicKeys { get; set; }

            public string[] Audiences { get; set; }

            public string[] Issuers { get; set; }

            public string CreateToken(IEnumerable<Claim> claims)
            {
                var key = Utils.Rsa.PrivateKeyFromPem(PrivateKey.Value);
                key.KeyId = PrivateKey.Key;

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature)
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
                ////var keys = PublicKeys.Select(kvp =>
                ////{
                ////    var key = Utils.Rsa.PublicKeyFromPem(kvp.Value);
                ////    key.KeyId = kvp.Key;

                ////    return key;
                ////});

                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidIssuers = Issuers,
                    ValidateAudience = true,
                    ValidAudiences = Audiences,
                    RequireExpirationTime = false,
                    RequireSignedTokens = true,
                    ////IssuerSigningKeys = keys,
                    IssuerSigningKeyResolver = (s, securityToken, kid, parameters) =>
                    {
                        if (PublicKeys.TryGetValue(kid, out var publicKey))
                        {
                            return new[]
                            {
                                Utils.Rsa.PublicKeyFromPem(publicKey)
                            };
                        }

                        return Enumerable.Empty<SecurityKey>();
                    }
                };

                var handler = new JwtSecurityTokenHandler();

                var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);

                return principal.Claims.ToList();
            }
        }

        public class ManualService : IJwtService
        {
            public KeyValuePair<string, string> PrivateKey { get; set; }

            public Dictionary<string, string> PublicKeys { get; set; }

            public string[] Audiences { get; set; }

            public string[] Issuers { get; set; }

            public string CreateToken(IEnumerable<Claim> claims)
            {
                var header = new
                {
                    alg = "RS256",
                    typ = "JWT",
                    kid = PrivateKey.Key
                };

                var payload = Utils.ConvertToDictionary(claims);

                var headerJson = Json(header);
                var payloadJson = Json(payload);

                var head = $"{Base64(headerJson)}.{Base64(payloadJson)}";

                var encodedSignature = Base64(Sign(GetBytes(head), PrivateKey.Value));

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

                if (header.kid == null)
                {
                    throw new Exception("Must specify kid");
                }

                if (!PublicKeys.TryGetValue((string)header.kid, out var publicKey))
                {
                    throw new Exception("Signature validation failed. Unable to match keys");
                }

                if (string.IsNullOrEmpty(encodedSignature))
                {
                    throw new Exception("Unable to validate signature, token does not have a signature");
                }

                var head = $"{encodedHeader}.{encodedPayload}";

                if (!Verify(GetBytes(head), FromBase64AsBytes(encodedSignature), publicKey))
                {
                    throw new Exception("Signature validation failed");
                }

                var payload = Utils.ParseClaims(FromBase64AsString(encodedPayload));

                if (!payload.Any(c => c.Type == "aud" && Audiences.Contains(c.Value)))
                {
                    throw new Exception("Audience validation failed");
                }

                if (payload.All(c => c.Type != "iss"))
                {
                    throw new Exception("Unable to validate issuer");
                }

                if (!payload.Any(c => c.Type == "iss" && Issuers.Contains(c.Value)))
                {
                    throw new Exception("Issuer validation failed");
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
