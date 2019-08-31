using Microsoft.EntityFrameworkCore.Design;

namespace Simple.Data
{
    public class ContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {

        }
    }
}
