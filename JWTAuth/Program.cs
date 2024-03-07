using System.Text;
using Asp.Versioning;
using JWTAuth.Dto;
using JWTAuth.Models;
using JWTAuth.Services;
using JWTAuth.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);


var jwtOptionSection = builder.Configuration.GetSection("Jwt");
builder.Services.Configure<JwtOptions>(jwtOptionSection);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(jwtOptions =>
{
    var configKey = jwtOptionSection["Key"] ?? throw new Exception("Configuration not configured!");
    var key = Encoding.UTF8.GetBytes(configKey);

    jwtOptions.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidIssuer = jwtOptionSection["Issuer"],
        ValidAudience = jwtOptionSection["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthorization();

builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.ReportApiVersions = true;
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
});

builder.Services.AddTransient<IJwtService, JwtService>();
builder.Services.AddTransient<IUserService, UserService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

var versionSet = app.NewApiVersionSet()
    .HasApiVersion(new ApiVersion(1.0))
    .ReportApiVersions()
    .Build();

app.MapPost("v{version:apiVersion}/token", [AllowAnonymous]([FromBody] UserInfo user,
    [FromServices] IUserService userService, [FromServices] IJwtService jwtService) =>
{
    var storedUser = userService.GetUser(user?.Username);
    if (!userService.IsAuthenticated(user?.Password, storedUser?.PasswordHash))
    {
        return Results.Unauthorized();
    }

    var tokenString = jwtService.GenerateToken(storedUser);
    return Results.Ok(new { token = tokenString });
}).WithApiVersionSet(versionSet);


app.MapGet("v{version:apiVersion}/weather", [Authorize]() =>
{
    var data = Enumerable.Range(1, 5)
        .Select(i => new WeatherForecast
        {
            Date = DateTime.Now.AddDays(i),
            TemperatureC = Random.Shared.Next(-20, 55)
        })
        .ToArray();

    return Results.Ok(data);
}).WithApiVersionSet(versionSet);


app.Run();