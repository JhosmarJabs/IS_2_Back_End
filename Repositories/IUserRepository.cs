using IS_2_Back_End.Entities;

namespace IS_2_Back_End.Repositories;

public interface IUserRepository
{
    Task<User?> GetByIdAsync(int id);
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByEmailWithRolesAsync(string email);
    Task<bool> EmailExistsAsync(string email);
    Task<User> CreateAsync(User user);
    Task UpdateAsync(User user);
    Task DeleteAsync(int id);

    Task<VerificationToken?> GetVerificationTokenAsync(string email, string token);
    Task CreateVerificationTokenAsync(VerificationToken verificationToken);
    Task UpdateVerificationTokenAsync(VerificationToken verificationToken);
    Task InvalidateOldVerificationTokensAsync(int userId);

    Task<RefreshToken?> GetRefreshTokenAsync(string tokenHash);
    Task CreateRefreshTokenAsync(RefreshToken refreshToken);
    Task UpdateRefreshTokenAsync(RefreshToken refreshToken);
    Task RevokeAllUserRefreshTokensAsync(int userId);
}