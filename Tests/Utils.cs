using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Xunit;

namespace Tests
{
    public static class Utils
    {
        public static string ToJson(object value) =>
            JsonConvert.SerializeObject(value);

        public static T FromJson<T>(string value) =>
            JsonConvert.DeserializeObject<T>(value);

        public static string ToBase64(byte[] bytes) =>
            Convert.ToBase64String(bytes)
                .Trim('=')
                .Replace('+', '-')
                .Replace('/', '_');

        public static string ToBase64(string value) =>
            ToBase64(Encoding.UTF8.GetBytes(value));

        public static string FromBase64(string value)
        {
            value = value.Replace('_', '/').Replace('-', '+');

            switch (value.Length % 4)
            {
                case 2:
                    value += "==";
                    break;
                case 3:
                    value += "=";
                    break;
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(value));
        }

        public static byte[] GenerateSecret()
        {
            using (var provider = new RNGCryptoServiceProvider())
            {
                byte[] byteArray = new byte[32];
                provider.GetBytes(byteArray);
                return byteArray;
            }
        }

        public static string GenerateSecretAsString() => Convert.ToBase64String(GenerateSecret());

        public static Dictionary<string, object> ConvertToDictionary(IEnumerable<Claim> claims)
        {
            var claimsByKey = claims.GroupBy(c => c.Type, c => c.Value);

            var result = new Dictionary<string, object>();
            foreach (var grp in claimsByKey)
            {
                if (grp.Count() == 1)
                {
                    result.Add(grp.Key, grp.Single());
                }
                else
                {
                    result.Add(grp.Key, grp.ToArray());
                }
            }

            return result;
        }

        public static ICollection<Claim> ParseClaims(string json)
        {
            var dict = FromJson<Dictionary<string, object>>(json);

            var result = new List<Claim>();
            foreach (var kvp in dict)
            {
                switch (kvp.Value)
                {
                    case string stringValue:
                        result.Add(new Claim(kvp.Key, stringValue));
                        break;
                    case JArray stringsValue:
                        result.AddRange(stringsValue.Select(x => new Claim(kvp.Key, x.Value<string>())));
                        break;
                    default:
                        throw new Exception($"I don't know how to handle {kvp.Value.GetType().Name}");

                }
            }

            return result;
        }

        public class RsaTests
        {
            [Fact]
            public void Can_Verify_Signature()
            {
                var data = Encoding.UTF8.GetBytes("Hello World");
                var hashAlgorithm = HashAlgorithmName.SHA256;
                var padding = RSASignaturePadding.Pkcs1;

                byte[] signature;
                using (var producer = RSA.Create(Rsa.PrivateKeyFromPem(Rsa.PrivateKey).Parameters))
                {
                    signature = producer.SignData(data, hashAlgorithm, padding);
                }

                using (var consumer = RSA.Create(Rsa.PublicKeyFromPem(Rsa.PublicKey).Parameters))
                {
                    Assert.True(consumer.VerifyData(data, signature, hashAlgorithm, padding));
                }
            }
        }

        public static class Rsa
        {
            public static RsaSecurityKey PrivateKeyFromPem(string keyPairPem)
            {
                var pemReader = new PemReader(new StringReader(keyPairPem));
                var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                var privateKeyParameters = (RsaPrivateCrtKeyParameters)keyPair.Private;
                var rsaParameters = DotNetUtilities.ToRSAParameters(privateKeyParameters);
                return new RsaSecurityKey(rsaParameters);
            }

            public static RsaSecurityKey PublicKeyFromPem(string publicKeyPem)
            {
                var pemReader = new PemReader(new StringReader(publicKeyPem));
                var publicKeyParameters = (RsaKeyParameters)pemReader.ReadObject();
                var rsaParameters = DotNetUtilities.ToRSAParameters(publicKeyParameters);
                return new RsaSecurityKey(rsaParameters);
            }

            /*
             * https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9
                ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
                # Don't add passphrase
                openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
                cat jwtRS256.key
                cat jwtRS256.key.pub
             */
            public static readonly string PrivateKey = @"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

            public static readonly string PublicKey = @"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz6Fx531Hyh/2O23dnsvb
WrpoxAHlO9SrnfA25tVeYpMAh1wR/3adfotjg/jREB2gwX3OTjaujnrofdndQkQn
bl1KPKpjndKz60ziJVbr7eFZKzMk5qYlJdwMCtAVgj+MIE59RKE+qNjEzujBN91z
80qkgGbJuH7rYZ+WGbInp3oH8wuTu6xgaGMn3yzTFdYXCie4BiR4t3ssCj6c743p
yGxiC6TjEqMNeIMJUSlbQKvxjdk/+yzVeeLLC2NWGeYUESjzkxaXGhUUiRPNsDxk
955qPdhkjYndJX8Bwi+BXc6PMDEuOaDz2bfaQ1byawuOYyZM+nblawyOa4H9u25G
dWqh6nbb1hQ29TXy4v9CqxfgNk124EJA/W9/YM4OF0zu0+z5bSLJh2y9I22hVn7w
CPZVNOp4kak0rRHVdHLQXJubC62cnWBYDu88tF7zfWPywU7hWHBrGZASSOF/gpza
KIf8VIs0Mfb18Z96P1j+zKSN0W3v3cKIhWWAUJxIToaBTK0ot4kKuW8nNYdUvR32
ujkRybZOHBlATKvMj1aL5UThYAfHCBtCGwd+khqjyg4BqZM0krsIasQlXgHMbMzD
/dbaKrPP4TjOvJC9BZ9op3hBHj9NV4t/4LUBi8UkP+kOYUDCbn/Uqi7evZhEOdgZ
Aiukz9T9N3rGQicvkaxHrq8CAwEAAQ==
-----END PUBLIC KEY-----";

            public static readonly string OtherPrivateKey = @"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

            public static readonly string OtherPublicKey = @"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxXlNVbMd7iJpHn7S4XkX
6NYPNEWmQYaO045A6DQZlxPnIUDpk7LoRU6jcdcfFoSDhwVqvQTrzKhwux4LN8gS
5hr/2S7x1Y5oDXMQ6BxeqWZ1+uKG0tTCEndN5en8e0ZT4HAjK16pQY/c4ySjYl9o
1OYSmEPNmL3jAzB+c+lsYO2Gw2zLkFO7xH+iSAdIfHlZYtmiw6urFnUB3lp3jg6E
F5O/M4iPWjcfd9Gi6v43T449hzFySXd+tW4bnesdsK9OQkYyw/5/9flxTVmxw8cE
5nV21BH0xoAERkx8boBeYFCPCzeIebbtVJ7t05FtCFEUpW3PxMErmPAZSDvBvkR+
0g7kQFfF1sjzmMiO8wwfX2BpVAPUsJbSAn6ezN3tWHGfJ+irJQQjGxA7JSMAEQ8J
moOPorH9BO8ElR4u69PrESbGrTuv9bIQjvRHsHnYDO/sbnu7np4XqMB8vDtzlbyZ
H6igagqv4hBl6vs47FurFrbQ9BGzNTq6kEPaxQ8Cuq1rDHj5QT3Np2sSWyz5J6TA
Lkd0HbsB526c0hvkTE+3Rp64twdJHhhKcoK+bkPYiShM4T3XP/V1y6JbWINM893d
v2ptkOtreZDzUXaU6DwLQ5k6JjMxaK3G8S38Jj4LORQ8OZUmEDRZXygIHuw38GlJ
0AO33+B8sxzDiXVq3R6+Wp0CAwEAAQ==
-----END PUBLIC KEY-----";
        }
    }
}