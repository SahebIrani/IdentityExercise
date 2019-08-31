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
    public class AppPasswordValidator<tUser> : UserValidator<tUser>
where tUser : User
    {
        private readonly ISet<string> _emailsBanList;
        private readonly ISet<string> _phoneNumberBanList;

        public AppPasswordValidator(IOptionsSnapshot<IdentitySettings> configurationRoot)
        {
            _emailsBanList = new HashSet<string>(configurationRoot.Value.EmailsBanList, StringComparer.OrdinalIgnoreCase);
            _phoneNumberBanList = new HashSet<string>(configurationRoot.Value.PhoneNumberBanList, StringComparer.OrdinalIgnoreCase);

            if (!_emailsBanList.Any())
                throw new InvalidOperationException("Please fill the emails ban list in the appsettings.json file.");
            if (!_phoneNumberBanList.Any())
                throw new InvalidOperationException("Please fill the phoneNumber ban list in the appsettings.json file.");
        }

        public Task<IdentityResult> ValidateAsync(UserManager<tUser> manager, tUser user)
        {
            var userName = user?.UserName;
            if (string.IsNullOrWhiteSpace(userName))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "EmailIsNotSet",
                    Description = "لطفا اطلاعات ایمیل را تکمیل کنید."
                }));

            if (_emailsBanList.Any(email => userName.EndsWith(email, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "BadEmailDomainError",
                    Description = "لطفا یک ایمیل پروایدر معتبر را وارد نمائید."
                }));

            if (string.IsNullOrWhiteSpace(userName))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "PhoneNumberIsNotSet",
                    Description = "شماره موبایل را تکمیل کنید."
                }));

            if (_phoneNumberBanList.Any(phone => phone == userName))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "BadPhoneNumberError",
                    Description = "لطفا یک شماره موبایل معتبر را وارد نمائید."
                }));

            var userEmail = user?.Email;
            if (string.IsNullOrWhiteSpace(userEmail))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "EmailIsNotSet",
                    Description = "لطفا اطلاعات ایمیل را تکمیل کنید."
                }));

            if (_emailsBanList.Any(email => userEmail.EndsWith(email, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = "BadEmailDomainError",
                    Description = "لطفا یک ایمیل پروایدر معتبر را وارد نمائید."
                }));

            var phoneNumber = user?.PhoneNumber;
            if (phoneNumber != null)
                if (_phoneNumberBanList.Any(phone => phone == phoneNumber))
                    return Task.FromResult(IdentityResult.Failed(new IdentityError
                    {
                        Code = "BadPhoneNumberError",
                        Description = "لطفا یک شماره موبایل معتبر را وارد نمائید."
                    }));

            return Task.FromResult(IdentityResult.Success);
        }
    }

}
