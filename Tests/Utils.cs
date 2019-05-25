using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

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
    }
}