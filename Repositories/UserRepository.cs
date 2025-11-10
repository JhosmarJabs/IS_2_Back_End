using IS_2_Back_End.Data;
using IS_2_Back_End.Entities;
using Microsoft.EntityFrameworkCore;

namespace IS_2_Back_End.Repositories;

public class UserRepository : IUserRepository
{
    private readonly AppDbContext _context;

    public UserRepository(AppDbContext context)
    {
        _context = context;
    }
    public async Task<bool> ExistsByPhoneAsync(string phone)
    {
        return await _context.Users.AnyAsync(u => u.Phone == phone);
    }


    public async Task<User?> GetByIdAsync(int id)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<User?> GetByEmailWithRolesAsync(string email)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<bool> EmailExistsAsync(string email)
    {
        return await _context.Users.AnyAsync(u => u.Email == email);
    }

    public async Task<User> CreateAsync(User user)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }

    public async Task UpdateAsync(User user)
    {
        user.UpdatedAt = DateTime.UtcNow;
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id)
    {
        var user = await _context.Users.FindAsync(id);
        if (user != null)
        {
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
        }
    }

    // Verification Tokens
    public async Task<VerificationToken?> GetVerificationTokenAsync(string email, string token)
    {
        return await _context.VerificationTokens
            .Include(vt => vt.User)
            .FirstOrDefaultAsync(vt =>
                vt.User.Email == email &&
                vt.Token == token &&
                !vt.Consumed &&
                vt.ExpiresAt > DateTime.UtcNow);
    }

    public async Task<VerificationToken?> GetVerificationTokenByPurposeAsync(string email, string token, string purpose)
    {
        return await _context.VerificationTokens
            .Include(vt => vt.User)
            .FirstOrDefaultAsync(vt =>
                vt.User.Email == email &&
                vt.Token == token &&
                vt.Purpose == purpose &&
                !vt.Consumed &&
                vt.ExpiresAt > DateTime.UtcNow);
    }

    public async Task<VerificationToken?> GetVerificationTokenByTokenAsync(string token, string purpose)
    {
        return await _context.VerificationTokens
            .Include(vt => vt.User)
            .FirstOrDefaultAsync(vt =>
                vt.Token == token &&
                vt.Purpose == purpose &&
                !vt.Consumed &&
                vt.ExpiresAt > DateTime.UtcNow);
    }

    public async Task CreateVerificationTokenAsync(VerificationToken verificationToken)
    {
        _context.VerificationTokens.Add(verificationToken);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateVerificationTokenAsync(VerificationToken verificationToken)
    {
        _context.VerificationTokens.Update(verificationToken);
        await _context.SaveChangesAsync();
    }

    public async Task InvalidateOldVerificationTokensAsync(int userId)
    {
        var oldTokens = await _context.VerificationTokens
            .Where(vt => vt.UserId == userId && !vt.Consumed)
            .ToListAsync();

        foreach (var token in oldTokens)
        {
            token.Consumed = true;
            token.ConsumedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();
    }

    public async Task InvalidateOldTokensByPurposeAsync(int userId, string purpose)
    {
        var oldTokens = await _context.VerificationTokens
            .Where(vt => vt.UserId == userId && vt.Purpose == purpose && !vt.Consumed)
            .ToListAsync();

        foreach (var token in oldTokens)
        {
            token.Consumed = true;
            token.ConsumedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();
    }

    // Refresh Tokens
    public async Task<RefreshToken?> GetRefreshTokenAsync(string tokenHash)
    {
        return await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt =>
                rt.TokenHash == tokenHash &&
                !rt.Revoked &&
                rt.ExpiresAt > DateTime.UtcNow);
    }

    public async Task CreateRefreshTokenAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateRefreshTokenAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Update(refreshToken);
        await _context.SaveChangesAsync();
    }

    public async Task RevokeAllUserRefreshTokensAsync(int userId)
    {
        var tokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.Revoked)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.Revoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();
    }
}