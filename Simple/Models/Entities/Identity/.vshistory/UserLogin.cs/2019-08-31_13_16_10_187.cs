using Microsoft.AspNetCore.Identity;

using System;

namespace Simple.Models.Entities.Identity
{
    public class UserLogin : IdentityUserLogin<int>
    {
        public User User { get; set; }

        public DateTime LoggedOn { get; set; }
    }
}