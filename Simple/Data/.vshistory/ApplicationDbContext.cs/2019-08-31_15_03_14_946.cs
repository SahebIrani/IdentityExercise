using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

using Simple.Models.Entities.Identity;

namespace Simple.Data
{
    public class ApplicationDbContext : IdentityDbContext<User, Role, int, UserClaim, UserRole, UserLogin, RoleClaim, UserToken>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            //base.OnModelCreating(builder);

            //builder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

            //foreach (Microsoft.EntityFrameworkCore.Metadata.IMutableEntityType entity in builder.Model.GetEntityTypes())
            //{
            //    //Microsoft.EntityFrameworkCore.Relational
            //    entity.GetDefaultTableName().Replace("AspNet", "");
            //    entity.Relational().TableName = entity.Relational().TableName.Replace("AspNet", "");
            //}
        }
    }
}