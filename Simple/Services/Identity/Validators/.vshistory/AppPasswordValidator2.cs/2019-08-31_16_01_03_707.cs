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
    public class AppPasswordvalidator<TUser> : IPasswordValidator<TUser> where TUser : User
    {
        public AppPasswordvalidator(IOptionsSnapshot<IdentitySettings> configurationRoot)
        {
            _passwordsBanList = new HashSet<string>(configurationRoot.Value.PasswordsBanList, StringComparer.OrdinalIgnoreCase);

            if (!_passwordsBanList.Any())
                throw new InvalidOperationException("لطفاً لیست ممنوعیت گذرواژه‌ها را در پرونده appsettings.json پر کنید.");
        }

        private readonly ISet<string> _passwordsBanList;

        public Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string passwords)
        {
            if (string.Equals(user.UserName, passwords, StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "UsernameAsPassword",
                    Description = "شما نمیتوانید نام کاربری خود را به عنوان رمز عبور خود استفاده کنید."
                }));

            if (string.IsNullOrWhiteSpace(password))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "PasswordIsNotSet",
                    Description = "لطفا کلمه‌ی عبور را تکمیل کنید."
                }));

            if (string.IsNullOrWhiteSpace(user?.UserName))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "UserNameIsNotSet",
                    Description = "لطفا نام کاربری را تکمیل کنید."
                }));

            if (password.ToLower().Contains(user.UserName.ToLower()))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "PasswordContainsUserName",
                    Description = "کلمه‌ی عبور نمی‌تواند حاوی قسمتی از نام کاربری باشد."
                }));

            if (!IsSafePasword(password))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "PasswordIsNotSafe",
                    Description = "کلمه‌ی عبور وارد شده به سادگی قابل حدس زدن است."
                }));

            return Task.FromResult(IdentityResult.Success);
        }

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
    }
}
