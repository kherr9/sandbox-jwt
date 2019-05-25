using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using Domain.Managers;
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
    }
}
