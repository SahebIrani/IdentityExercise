using Microsoft.AspNetCore.Identity;

Simple.Models.Entities.Identity{

using System;
public class UserRole : IdentityUserRole<int>
{
    public User User { get; set; }

    public Role Role { get; set; }

    public DateTime GivenOn { get; set; }
}
}