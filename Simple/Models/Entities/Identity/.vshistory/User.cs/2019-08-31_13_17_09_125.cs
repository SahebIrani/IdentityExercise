using Microsoft.AspNetCore.Identity;

using System.Collections.Generic;

namespace Simple.Models.Entities.Identity
{
    public class User : IdentityUser<int>
    {
        public string FirstName { get; set; }

        public string LastName { get; set; }

        public short Age { get; set; }

        public ICollection<UserRole> Roles { get; set; }

        public ICollection<UserLogin> Logins { get; set; }

        public ICollection<UserClaim> Claims { get; set; }

        public ICollection<UserToken> Tokens { get; set; }
    }
}