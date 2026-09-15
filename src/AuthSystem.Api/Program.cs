using AuthSystem.Api.Data;
using AuthSystem.Api.Models;
using AuthSystem.Api.Options;
using AuthSystem.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
    ?? throw new InvalidOperationException("Missing 'Jwt' configuration section.");

// Signing keys never live in a committed file: they come from user-secrets in
// development and from Jwt__PrivateKey / Jwt__Secret everywhere else. The provider
// validates the key material and throws with an actionable message, so a missing or
// weak key stops startup instead of silently producing forgeable tokens.
var keyProvider = new JwtKeyProvider(Microsoft.Extensions.Options.Options.Create(jwtOptions));
builder.Services.AddSingleton<IJwtKeyProvider>(keyProvider);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
    })
    .AddRoles<ApplicationRole>()
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
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keyProvider.ValidationKeys,
            // Pinning the algorithms is what closes algorithm confusion: without this the
            // token's own header decides how it gets verified, so 'alg: none' or an HMAC
            // signature computed over the RSA public key would be accepted.
            ValidAlgorithms = keyProvider.ValidAlgorithms,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    });

// The audience validator needs the application registry, which needs the database, so
// it is wired here rather than inline above: Configure<T> resolves the dependency from
// the container once the provider exists, with no second provider built by hand.
builder.Services
    .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IClientApplicationService>((options, registry) =>
    {
        // Audiences come from the client application registry, not from config: a new
        // consumer is registered once in the database and every instance accepts it
        // without a redeploy. The token still has to name exactly one of them, so a
        // token minted for one application is rejected by all the others.
        options.TokenValidationParameters.AudienceValidator = (audiences, _, _) =>
            audiences is not null
            && audiences.Any(a => registry.GetActiveAudiences().Contains(a, StringComparer.Ordinal));
    });

builder.Services.AddAuthorization();
builder.Services.AddMemoryCache();
builder.Services.AddScoped<ITokenService, TokenService>();
// Scoped, not singleton: the challenge store now writes to the database, so every
// instance sees the same pending challenges and the service can be load balanced.
builder.Services.AddScoped<IMfaChallengeStore, DbMfaChallengeStore>();
builder.Services.AddSingleton<IClientApplicationService, ClientApplicationService>();

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.MigrateAsync();
    await DataSeeder.SeedAsync(scope.ServiceProvider);

    // Load the audience snapshot before the first request, so nothing is validated
    // against an empty list.
    await scope.ServiceProvider.GetRequiredService<IClientApplicationService>().RefreshAsync();
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
