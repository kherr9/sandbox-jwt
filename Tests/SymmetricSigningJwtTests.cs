using System;
using System.Security.Claims;
using System.Text;
using Domain.Managers;
using Newtonsoft.Json;
using Xunit;

namespace Tests
{
    public class SymmetricSigningJwtTests
    {
        [Fact]
        public void Can_Verify()
        {
            var model = new JwtContainerModel
            {
                Claims = new[]
                {
                    new Claim(ClaimTypes.Name, "Kevin Herr"),
                    new Claim(ClaimTypes.Email, "kherr@example.com"),
                }
            };

            var authService = new JwtAuthService();

            var token = authService.GenerateToken(model);

            var principal = authService.ValidateToken(token, out var validatedToken);
        }

        [Fact]
        public void Can_Create_Token_Manually()
        {
            var header = new
            {
                alg = "HS256",
                typ = "JWT"
            };

            var payload = new
            {
                unique_name = "alice@example.com",
                email = "alice@example.com"
            };
        }
    }

    public static class Utils
    {
        public static string ToJson(object value) =>
            JsonConvert.SerializeObject(value);

        public static T FromJson<T>(string value) =>
            JsonConvert.DeserializeObject<T>(value);

        public static string ToBase64(string value) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
                .Replace("=", "")
                .Replace('+', '-')
                .Replace('/', '_');

        public static string FromBase64(string value) =>
            Encoding.UTF8.GetString(Convert.FromBase64String(value));
    }
}
