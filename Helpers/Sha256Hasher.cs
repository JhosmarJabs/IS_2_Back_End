using System.Security.Cryptography;
using System.Text;

namespace IS_2_Back_End.Helpers;

public class Sha256Hasher
{
    public string GenerateSalt()
    {
        var saltBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(saltBytes);
        return Convert.ToBase64String(saltBytes);
    }

    public string HashPassword(string password, string salt)
    {
        using var sha256 = SHA256.Create();
        var passwordWithSalt = password + salt;
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(passwordWithSalt));
        return Convert.ToBase64String(hashedBytes);
    }

    public bool VerifyPassword(string password, string salt, string hashedPassword)
    {
        var hashOfInput = HashPassword(password, salt);
        return hashOfInput == hashedPassword;
    }
}