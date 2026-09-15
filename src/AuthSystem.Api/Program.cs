using System.Text;
using AuthSystem.Api.Data;
using AuthSystem.Api.Models;
using AuthSystem.Api.Options;
using AuthSystem.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
    ?? throw new InvalidOperationException("Missing 'Jwt' configuration section.");

// The signing key never lives in a committed file: it comes from user-secrets in
// development and from the Jwt__Secret environment variable everywhere else. Fail
// fast and loudly instead of falling back to anything insecure.
if (string.IsNullOrWhiteSpace(jwtOptions.Secret))
{
    throw new InvalidOperationException(
        "Jwt:Secret is not configured. The API refuses to start without a signing key. " +
        "Local development: run 'dotnet user-secrets set \"Jwt:Secret\" \"<key>\"' from src/AuthSystem.Api. " +
        "Deployment: set the Jwt__Secret environment variable. " +
        "Generate a key with: openssl rand -base64 48");
}

var signingKeyBytes = Encoding.UTF8.GetBytes(jwtOptions.Secret);
if (signingKeyBytes.Length < 32)
{
    throw new InvalidOperationException(
        $"Jwt:Secret is too short: {signingKeyBytes.Length} bytes. HS256 requires a key of at least " +
        "32 bytes (256 bits). Generate one with: openssl rand -base64 48");
}

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default")));

builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
    })
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddMemoryCache();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddSingleton<IMfaChallengeStore, MfaChallengeStore>();

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.MigrateAsync();
    await RoleSeeder.SeedAsync(scope.ServiceProvider);
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

public partial class Program;
