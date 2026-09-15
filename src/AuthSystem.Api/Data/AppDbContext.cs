using AuthSystem.Api.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options)
    : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>(options)
{
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<ClientApplication> ClientApplications => Set<ClientApplication>();
    public DbSet<MfaChallenge> MfaChallenges => Set<MfaChallenge>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasIndex(rt => rt.TokenHash).IsUnique();

            entity.HasOne(rt => rt.User)
                .WithMany()
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // A refresh token is bound to the application it was issued for, so it can
            // only ever be exchanged for an access token with that same audience.
            entity.HasOne<ClientApplication>()
                .WithMany()
                .HasForeignKey(rt => rt.ClientApplicationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ClientApplication>(entity =>
        {
            entity.HasIndex(a => a.ClientId).IsUnique();
            entity.HasIndex(a => a.Audience).IsUnique();
            entity.Property(a => a.ClientId).HasMaxLength(128);
            entity.Property(a => a.Audience).HasMaxLength(256);
            entity.Property(a => a.DisplayName).HasMaxLength(256);
        });

        builder.Entity<ApplicationRole>(entity =>
        {
            entity.Property(r => r.RoleName).HasMaxLength(128);

            entity.HasOne<ClientApplication>()
                .WithMany()
                .HasForeignKey(r => r.ClientApplicationId)
                .OnDelete(DeleteBehavior.Cascade);

            // One role name per application; the globally unique index Identity puts on
            // NormalizedName is satisfied by the qualified "clientId:Role" form.
            entity.HasIndex(r => new { r.ClientApplicationId, r.RoleName }).IsUnique();
        });

        builder.Entity<MfaChallenge>(entity =>
        {
            entity.HasIndex(c => c.TokenHash).IsUnique();
            entity.HasIndex(c => c.ExpiresAtUtc);
            entity.Property(c => c.TokenHash).HasMaxLength(64);

            entity.HasOne<ApplicationUser>()
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
