using JWTAuth.Dto;

namespace JWTAuth.Services.Interfaces;

public interface IUserService
{
    UserDto? GetUser(string? username);
    bool IsAuthenticated(string? password, string? passwordHash);
}