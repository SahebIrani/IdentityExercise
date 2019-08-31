using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Simple.Data;
using Simple.Models.Entities.Identity;
using Simple.Services.Identity.Managers;
using Simple.Services.Identity.Stores;
using Simple.Services.Identity.Validators;

using System;
using System.Linq;
using System.Security.Claims;

namespace Simple
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.AddDefaultIdentity<IdentityUser>(options =>
                 options.SignIn.RequireConfirmedAccount = true
            )
                //.AddEntityFrameworkStores<ApplicationDbContext>()
                //.AddDefaultTokenProviders()
                .AddUserStore<AppUserStore>()
                .AddRoleStore<AppRoleStore>()
                .AddSignInManager<AppSignInManager>()
                .AddUserManager<AppUserManager>()
                .AddRoleManager<AppRoleManager>()
                .AddUserValidator<AppUserValidator>()
                .AddRoleValidator<AppRoleValidator>()
            ;

            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });

            using IServiceScope scope = app.ApplicationServices.CreateScope();
            IServiceProvider scopeServiceProvider = scope.ServiceProvider;
            ApplicationDbContext context = scopeServiceProvider.GetRequiredService<ApplicationDbContext>();
            if (context != null && context.Database.GetPendingMigrations().Any())
            {
                context.Database.Migrate();

                if (!context.Users.Any())
                {
                    const string defaultAdminUserName = "IdentitySeedData:DefaultAdminUserName";
                    const string defaultAdminPassword = "IdentitySeedData:DefaultAdminPassword";

                    UserManager<User> userManager = scopeServiceProvider.GetRequiredService<UserManager<User>>();
                    RoleManager<Role> roleManager = scopeServiceProvider.GetRequiredService<RoleManager<Role>>();
                    User admin = userManager.FindByNameAsync(Configuration[defaultAdminUserName]).GetAwaiter().GetResult();
                    if (admin == null)
                    {
                        Role adminRoleName = new Role { Name = "admin" };
                        Role userRoleName = new Role { Name = "user" };
                        roleManager.CreateAsync(adminRoleName).GetAwaiter().GetResult();
                        roleManager.CreateAsync(userRoleName).GetAwaiter().GetResult();
                        admin = new User { UserName = Configuration[defaultAdminUserName], Email = Configuration[defaultAdminUserName], FirstName = "مدیر", LastName = "سایت", EmailConfirmed = true, LockoutEnabled = false };
                        IdentityResult identityResult = userManager.CreateAsync(admin, Configuration[defaultAdminPassword]).GetAwaiter().GetResult();
                        userManager.AddToRoleAsync(admin, "admin").GetAwaiter().GetResult();
                        userManager.AddToRoleAsync(admin, "user").GetAwaiter().GetResult();
                        Claim adminClaimName = new Claim(ClaimTypes.Role, "admin");
                        userManager.AddClaimAsync(admin, adminClaimName).GetAwaiter().GetResult();
                        roleManager.AddClaimAsync(adminRoleName, adminClaimName).GetAwaiter().GetResult();
                    }
                }
            }
        }
    }
}