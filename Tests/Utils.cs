using System;
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

        public static string ToBase64(string value) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
                .Trim('=')
                .Replace('+', '-')
                .Replace('/', '_');

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
    }
}