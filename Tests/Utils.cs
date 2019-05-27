using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

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
    }
}