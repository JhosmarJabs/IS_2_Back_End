using System.ComponentModel.DataAnnotations;

namespace IS_2_Back_End.DTOs.Auth;

// Prevalidación
public class PrevalidateRequest
{
    [Required(ErrorMessage = "El email es requerido")]
    [EmailAddress(ErrorMessage = "El formato del email no es válido")]
    public string Email { get; set; } = string.Empty;
}

public class PrevalidateResponse
{
    public bool EmailExists { get; set; }
    public bool IsVerified { get; set; }
    public bool CanLogin { get; set; }
    public List<string> AvailableLoginMethods { get; set; } = new();
}

// Verificación genérica de token
public class VerifyGenericTokenRequest
{
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Token { get; set; } = string.Empty;

    [Required]
    public string Purpose { get; set; } = string.Empty; // "email_verification", "otp", "magic_link", "password_reset"
}

// Login con password
public class LoginPasswordRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}

// Request OTP para login
public class LoginPasswordRequestOtpRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}

// Login con OTP
public class LoginOtpRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string OtpCode { get; set; } = string.Empty;
}

// Request Magic Link
public class MagicLinkRequestRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

// Login con Magic Link
public class MagicLinkLoginRequest
{
    [Required]
    public string Token { get; set; } = string.Empty;
}

// OAuth Google
public class GoogleOAuthRequest
{
    [Required]
    public string IdToken { get; set; } = string.Empty;
}

public class GoogleOAuthResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string TokenType { get; set; } = "Bearer";
    public bool IsNewUser { get; set; }
    public UserInfo User { get; set; } = new();
}

public class UserInfo
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? Nombre { get; set; }
    public string? Apellido { get; set; }
}

// Password Reset
public class RequestPasswordResetRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

public class ResetPasswordRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Token { get; set; } = string.Empty;

    [Required]
    [MinLength(8)]
    public string NewPassword { get; set; } = string.Empty;
}