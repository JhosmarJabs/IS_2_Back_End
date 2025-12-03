using System.ComponentModel.DataAnnotations;

namespace IS_2_Back_End.DTOs.Auth;

// MFA Setup Request
public class MfaSetupRequest
{
    [Required]
    public int UserId { get; set; }
}

public class MfaSetupResponse
{
    public string QrCodeUrl { get; set; } = string.Empty;
    public string Secret { get; set; } = string.Empty;
    public string Message { get; set; } = "Escanea el código QR con tu aplicación de autenticación (Google Authenticator, Authy, etc.)";
}

// MFA Enable Request
public class MfaEnableRequest
{
    [Required]
    public int UserId { get; set; }

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string VerificationCode { get; set; } = string.Empty;
}

// MFA Verify Request
public class MfaVerifyRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string Code { get; set; } = string.Empty;
}

// MFA Disable Request
public class MfaDisableRequest
{
    [Required]
    public int UserId { get; set; }

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string VerificationCode { get; set; } = string.Empty;
}

// Backup Codes Response
public class BackupCodesResponse
{
    public List<string> Codes { get; set; } = new();
    public string Message { get; set; } = "Guarda estos códigos en un lugar seguro. Cada código solo puede usarse una vez.";
}

// Login con MFA Request
public class LoginWithMfaRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    [Required]
    [StringLength(8, MinimumLength = 6)]
    public string MfaCode { get; set; } = string.Empty; // Puede ser código TOTP o backup code
}