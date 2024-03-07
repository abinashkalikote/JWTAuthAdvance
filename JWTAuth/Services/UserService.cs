using JWTAuth.Dto;
using JWTAuth.Services.Interfaces;

namespace JWTAuth.Services;

public class UserService : IUserService
{
    private readonly List<UserDto> _users;

    public UserService()
    {
        _users = new List<UserDto>()
        {
            new(Guid.NewGuid(), "user1", BCrypt.Net.BCrypt.HashPassword("password1"), "user1@gmail.com", "Admin"),
            new(Guid.NewGuid(), "user2", BCrypt.Net.BCrypt.HashPassword("password2"), "user2@gmail.com", "User")
        };
    }
    
    public UserDto? GetUser(string? username)
    {
        ArgumentNullException.ThrowIfNull(username);
        return _users.SingleOrDefault(e => e.Username == username);
    }

    public bool IsAuthenticated(string? password, string? passwordHash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(passwordHash);

        return BCrypt.Net.BCrypt.Verify(password, passwordHash);
    }
}