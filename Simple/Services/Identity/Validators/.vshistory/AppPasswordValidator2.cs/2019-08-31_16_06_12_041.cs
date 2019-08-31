using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

using Simple.Models.Configures;
using Simple.Models.Entities.Identity;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Simple.Services.Identity.Validators
{
    public class AppPasswordvalidator<TUser> : PasswordValidator<TUser> where TUser : User
    {
        public AppPasswordvalidator(IOptionsSnapshot<IdentitySettings> configurationRoot)
        {
            _passwordsBanList = new HashSet<string>(configurationRoot.Value.PasswordsBanList, StringComparer.OrdinalIgnoreCase);

            if (!_passwordsBanList.Any())
                throw new InvalidOperationException("لطفاً لیست ممنوعیت گذرواژه‌ها را در پرونده appsettings.json پر کنید.");
        }

        private readonly ISet<string> _passwordsBanList;



        private bool IsSafePasword(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
                return false;

            if (data.Length < 5)
                return false;

            if (_passwordsBanList.Contains(data.ToLowerInvariant()))
                return false;

            if (AreAllCharsEuqal(data))
                return false;

            return true;
        }
        private static bool AreAllCharsEuqal(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
                return false;

            data = data.ToLowerInvariant();
            var firstElement = data.ElementAt(0);
            var euqalCharsLen = data.ToCharArray().Count(x => x == firstElement);
            if (euqalCharsLen == data.Length)
                return true;

            return false;
        }

        public override Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            throw new NotImplementedException();
        }
    }
}
