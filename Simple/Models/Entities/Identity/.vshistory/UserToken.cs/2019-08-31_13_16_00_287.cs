using App.Domain.Identity;

using Microsoft.AspNetCore.Identity;

using System;

namespace Simple.Models.Entities.Identity
{
    public class UserToken : IdentityUserToken<int>
    {
        public User User { get; set; }

        public DateTime GeneratedOn { get; set; }
    }
}