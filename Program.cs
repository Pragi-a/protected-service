using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using ProtectedService.Authorization;

const string identityIssuer = "http://localhost:5101";
const string audience = "protected-service";

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
    .WithOrigins("http://localhost:4200", "http://localhost:4201")
    .AllowAnyHeader()
    .AllowAnyMethod()));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.Authority = identityIssuer;
    options.RequireHttpsMetadata = false;
    options.Audience = audience;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = identityIssuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        NameClaimType = ClaimTypes.Name,
        RoleClaimType = ClaimTypes.Role
    };
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();

var app = builder.Build();
var items = new List<DemoItem>();
var itemsLock = new object();
var nextItemId = 1;
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/", () => Results.Ok(new { service = "protected-service", audience }));
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/api/secure/message", (ClaimsPrincipal user) => Results.Ok(new
{
    message = "Token accepted. The protected service validated its RS256 signature using Identity's JWKS public key.",
    subject = user.FindFirstValue("sub"),
    name = user.Identity?.Name,
    role = user.FindFirstValue(ClaimTypes.Role),
    scope = user.FindFirstValue("scope")
})).RequireAuthorization();

app.MapGet("/api/items", () =>
{
    lock (itemsLock) return Results.Ok(items);
}).RequireAuthorization("Permission:read");

app.MapPost("/api/items", (ItemRequest request) =>
{
    var name = request.Name.Trim();
    if (string.IsNullOrWhiteSpace(name)) return Results.BadRequest(new { message = "Item name is required." });
    lock (itemsLock)
    {
        if (items.Count >= 5) return Results.Conflict(new { message = "Only five in-memory items are allowed." });
        var item = new DemoItem(nextItemId++, name);
        items.Add(item);
        return Results.Created($"/api/items/{item.Id}", item);
    }
}).RequireAuthorization("Permission:add");

app.MapPut("/api/items/{id:int}", (int id, ItemRequest request) =>
{
    var name = request.Name.Trim();
    if (string.IsNullOrWhiteSpace(name)) return Results.BadRequest(new { message = "Item name is required." });
    lock (itemsLock)
    {
        var index = items.FindIndex(item => item.Id == id);
        if (index < 0) return Results.NotFound();
        var item = new DemoItem(id, name);
        items[index] = item;
        return Results.Ok(item);
    }
}).RequireAuthorization("Permission:update");

app.MapDelete("/api/items/{id:int}", (int id) =>
{
    lock (itemsLock)
    {
        var item = items.FirstOrDefault(item => item.Id == id);
        if (item is null) return Results.NotFound();
        items.Remove(item);
        return Results.NoContent();
    }
}).RequireAuthorization("Permission:delete");
app.Run();
record ItemRequest(string Name);
record DemoItem(int Id, string Name);
