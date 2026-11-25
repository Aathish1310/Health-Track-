using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using HealthTrack.Data;
using HealthTrack.Models;
using HealthTrack.Services;

var builder = WebApplication.CreateBuilder(args);

// ---- Storage location (App_Data by default) ----
var configuredPath = builder.Configuration["Storage:DataPath"];
var dataPath = string.IsNullOrWhiteSpace(configuredPath)
    ? Path.Combine(builder.Environment.ContentRootPath, "App_Data")
    : configuredPath;
Directory.CreateDirectory(dataPath);

// ---- Encryption keys for data at rest (Data Protection API) ----
var dp = builder.Services.AddDataProtection()
    .SetApplicationName("HealthTrack")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataPath, "keys")));
if (OperatingSystem.IsWindows()) dp.ProtectKeysWithDpapi();   // keys are themselves encrypted for the Windows user

var encrypt = builder.Configuration.GetValue("Security:EncryptDataAtRest", true);
builder.Services.AddSingleton(sp => new DataStore(dataPath, sp.GetRequiredService<IDataProtectionProvider>(), encrypt));
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<NotificationService>();
builder.Services.AddScoped<ReminderService>();
builder.Services.AddScoped<AnalyticsService>();
builder.Services.AddHostedService<ReminderBackgroundService>();

// ---- Authentication (cookie) ----
var sessionMinutes = Math.Clamp(builder.Configuration.GetValue("Security:SessionMinutes", 30), 5, 480);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/Account/Login";
        o.AccessDeniedPath = "/Account/AccessDenied";
        o.Cookie.Name = "HealthTrack.Auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(sessionMinutes);
        o.SlidingExpiration = true;
        // Every request: make sure the account still exists, is active and still has the same role.
        o.Events.OnValidatePrincipal = async ctx =>
        {
            var store = ctx.HttpContext.RequestServices.GetRequiredService<DataStore>();
            var u = store.Users.Find(ctx.Principal.GetUserId());
            if (u == null || !u.IsActive || !u.IsApproved || u.Role != ctx.Principal.GetRole())
            {
                ctx.RejectPrincipal();
                await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
        };
    });
builder.Services.AddAuthorization();

builder.Services.AddAntiforgery(o => { o.Cookie.Name = "HealthTrack.Antiforgery"; o.Cookie.HttpOnly = true; });
builder.Services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

var app = builder.Build();

SeedData.Run(app.Services.GetRequiredService<DataStore>(), builder.Configuration.GetValue("Seed:CreateDemoData", true));

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
    app.UseHttpsRedirection();
}
app.UseStatusCodePagesWithReExecute("/Home/Error", "?code={0}");

// ---- Security headers ----
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    h["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; form-action 'self'";
    if (ctx.User?.Identity?.IsAuthenticated == true) h["Cache-Control"] = "no-store";   // never cache health data
    await next();
});

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");

app.Run();
