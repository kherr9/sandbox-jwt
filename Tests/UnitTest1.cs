using System;
using System.Text;
using Newtonsoft.Json;
using Xunit;

namespace Tests
{
    public class UnitTest1
    {
        [Fact]
        public void Unsecure_Jwt()
        {
            var header = new Header
            {
                alg = "none"
            };

            var payload = new
            {
                sub = "kherr9@gmail.com",
                name = "Kevin Herr"
            };

            var jwt = Encode(header, payload);
        }

        private static string Encode(Header header, object payload)
        {
            return $"{ToBase64(ToJson(header))}.{ToBase64(ToJson(payload))}";
        }

        private static string ToBase64(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
                .Replace("=", "")
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private static string ToJson(object obj) => JsonConvert.SerializeObject(obj);
    }

    public class Header
    {
        public string alg { get; set; }
    }

    public class Payload
    {
        public string sub { get; set; }

        public string name { get; set; }
    }
}
