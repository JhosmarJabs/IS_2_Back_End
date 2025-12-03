using IS_2_Back_End.Attributes;
using IS_2_Back_End.Document;
using IS_2_Back_End.Entities;
using IS_2_Back_End.Helpers;
using IS_2_Back_End.Repositories;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IS_2_Back_End.Services;

/// <summary>
/// Servicio de autenticación multifactor (MFA)
/// REQ-020: Implementación de segundo factor obligatorio
/// </summary>
//[Requirement(Requirements.MFA_REQUIRED, "Implementación de autenticación multifactor")]
public interface IMfaService
{
    Task<string> GenerateMfaSecretAsync(int userId);
    Task<bool> EnableMfaAsync(int userId, string verificationCode);
    Task<bool> VerifyMfaCodeAsync(int userId, string code);
    Task<bool> DisableMfaAsync(int userId, string verificationCode);
    Task<List<string>> GenerateBackupCodesAsync(int userId);
    Task<bool> VerifyBackupCodeAsync(int userId, string backupCode);
}

public class MfaService : IMfaService
{
    private readonly IUserRepository _userRepository;
    private readonly N8nClient _n8nClient;

    public MfaService(IUserRepository userRepository, N8nClient n8nClient)
    {
        _userRepository = userRepository;
        _n8nClient = n8nClient;
    }

    public async Task<string> GenerateMfaSecretAsync(int userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new InvalidOperationException("Usuario no encontrado");

        var secret = GenerateBase32Secret();

        // Guardar secret temporalmente en VerificationToken
        var token = new VerificationToken
        {
            UserId = userId,
            Token = secret,
            Purpose = "mfa_setup",
            Payload = JsonSerializer.Serialize(new { setupTime = DateTime.UtcNow }),
            ExpiresAt = DateTime.UtcNow.AddMinutes(30),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(token);

        // Retornar formato para QR: otpauth://totp/FloriaBautista:user@email.com?secret=SECRET&issuer=FloriaBautista
        return $"otpauth://totp/FloriaBautista:{user.Email}?secret={secret}&issuer=FloriaBautista";
    }

    public async Task<bool> EnableMfaAsync(int userId, string verificationCode)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new InvalidOperationException("Usuario no encontrado");

        // Buscar el secret temporal
        var setupToken = await _userRepository.GetVerificationTokenByPurposeAsync(
            user.Email, "", "mfa_setup");

        if (setupToken == null)
            throw new InvalidOperationException("No hay configuración MFA pendiente");

        var secret = setupToken.Token;

        // Verificar código
        if (!VerifyTotpCode(secret, verificationCode))
            throw new InvalidOperationException("Código de verificación inválido");

        // Guardar secret permanentemente en Payload del usuario
        var mfaData = new
        {
            enabled = true,
            secret = secret,
            enabledAt = DateTime.UtcNow
        };

        // Crear token permanente para MFA
        var mfaToken = new VerificationToken
        {
            UserId = userId,
            Token = secret,
            Purpose = "mfa_enabled",
            Payload = JsonSerializer.Serialize(mfaData),
            ExpiresAt = DateTime.UtcNow.AddYears(10), // Permanente
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(mfaToken);

        // Invalidar token de setup
        setupToken.Consumed = true;
        setupToken.ConsumedAt = DateTime.UtcNow;
        await _userRepository.UpdateVerificationTokenAsync(setupToken);

        return true;
    }

    public async Task<bool> VerifyMfaCodeAsync(int userId, string code)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            return false;

        // Buscar configuración MFA activa
        var mfaToken = await _userRepository.GetVerificationTokenByPurposeAsync(
            user.Email, "", "mfa_enabled");

        if (mfaToken == null || mfaToken.Consumed)
            return false;

        var secret = mfaToken.Token;
        return VerifyTotpCode(secret, code);
    }

    public async Task<bool> DisableMfaAsync(int userId, string verificationCode)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new InvalidOperationException("Usuario no encontrado");

        var mfaToken = await _userRepository.GetVerificationTokenByPurposeAsync(
            user.Email, "", "mfa_enabled");

        if (mfaToken == null)
            throw new InvalidOperationException("MFA no está habilitado");

        // Verificar código antes de deshabilitar
        if (!VerifyTotpCode(mfaToken.Token, verificationCode))
            throw new InvalidOperationException("Código de verificación inválido");

        mfaToken.Consumed = true;
        mfaToken.ConsumedAt = DateTime.UtcNow;
        await _userRepository.UpdateVerificationTokenAsync(mfaToken);

        return true;
    }

    public async Task<List<string>> GenerateBackupCodesAsync(int userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new InvalidOperationException("Usuario no encontrado");

        var backupCodes = new List<string>();
        for (int i = 0; i < 10; i++)
        {
            backupCodes.Add(GenerateBackupCode());
        }

        // Guardar códigos hasheados
        var hashedCodes = backupCodes.Select(code => HashBackupCode(code)).ToList();

        var backupToken = new VerificationToken
        {
            UserId = userId,
            Token = string.Join(",", hashedCodes),
            Purpose = "mfa_backup_codes",
            Payload = JsonSerializer.Serialize(new { generatedAt = DateTime.UtcNow }),
            ExpiresAt = DateTime.UtcNow.AddYears(1),
            CreatedAt = DateTime.UtcNow
        };

        // Invalidar códigos antiguos
        await _userRepository.InvalidateOldTokensByPurposeAsync(userId, "mfa_backup_codes");
        await _userRepository.CreateVerificationTokenAsync(backupToken);

        return backupCodes;
    }

    public async Task<bool> VerifyBackupCodeAsync(int userId, string backupCode)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            return false;

        var backupToken = await _userRepository.GetVerificationTokenByPurposeAsync(
            user.Email, "", "mfa_backup_codes");

        if (backupToken == null)
            return false;

        var hashedCodes = backupToken.Token.Split(',').ToList();
        var hashedInput = HashBackupCode(backupCode);

        if (hashedCodes.Contains(hashedInput))
        {
            // Remover código usado
            hashedCodes.Remove(hashedInput);
            backupToken.Token = string.Join(",", hashedCodes);
            await _userRepository.UpdateVerificationTokenAsync(backupToken);
            return true;
        }

        return false;
    }

    #region Helper Methods

    private string GenerateBase32Secret()
    {
        const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var random = new byte[20];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(random);

        var result = new StringBuilder(32);
        for (int i = 0; i < 32; i++)
        {
            result.Append(base32Chars[random[i % 20] % 32]);
        }

        return result.ToString();
    }

    private bool VerifyTotpCode(string secret, string code)
    {
        if (string.IsNullOrEmpty(code) || code.Length != 6)
            return false;

        var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timeStep = unixTime / 30;

        // Verificar código actual y ±1 ventana para compensar sincronización
        for (long i = -1; i <= 1; i++)
        {
            var generatedCode = GenerateTotpCode(secret, timeStep + i);
            if (generatedCode == code)
                return true;
        }

        return false;
    }

    private string GenerateTotpCode(string secret, long timeStep)
    {
        var key = Base32Decode(secret);
        var timeBytes = BitConverter.GetBytes(timeStep);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timeBytes);

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(timeBytes);

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);

        var otp = binary % 1000000;
        return otp.ToString("D6");
    }

    private byte[] Base32Decode(string base32)
    {
        const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        base32 = base32.TrimEnd('=').ToUpper();

        var bits = new List<bool>();
        foreach (var c in base32)
        {
            var value = base32Chars.IndexOf(c);
            if (value < 0)
                throw new ArgumentException("Carácter inválido en Base32");

            for (int i = 4; i >= 0; i--)
                bits.Add((value & (1 << i)) != 0);
        }

        var bytes = new byte[bits.Count / 8];
        for (int i = 0; i < bytes.Length; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                if (bits[i * 8 + j])
                    bytes[i] |= (byte)(1 << (7 - j));
            }
        }

        return bytes;
    }

    private string GenerateBackupCode()
    {
        var random = new byte[4];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(random);

        var code = BitConverter.ToUInt32(random, 0) % 100000000;
        return code.ToString("D8");
    }

    private string HashBackupCode(string code)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(code);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    #endregion
}