using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AutenticacaoJWT.Database
{
    public class AppDbContext : IdentityDbContext<User>
    {
        private IConfiguration _config;
        public AppDbContext(IConfiguration config, DbContextOptions<AppDbContext> options) : base(options)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            var typeDataBase = _config["TypeDatabase"];
            var conectionString = _config.GetConnectionString(typeDataBase);

            optionsBuilder.UseNpgsql(conectionString);
            base.OnConfiguring(optionsBuilder);
        }
    }
}
