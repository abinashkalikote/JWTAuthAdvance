using JWTAuth.Dto;

namespace JWTAuth.Services.Interfaces;
public interface IJwtService
{
    string GenerateToken(UserDto? user);
}