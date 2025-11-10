using IS_2_Back_End.DTOs.Auth;
using IS_2_Back_End.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IS_2_Back_End.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    #region Registro y Verificación

    /// <summary>
    /// Registra un nuevo usuario
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            
            var user = await _authService.RegisterAsync(request);
            return Ok(new
            {
                message = "Usuario registrado exitosamente. Revisa tu email para verificar tu cuenta.",
                user
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    /// <summary>
    /// Verifica el email del usuario (legacy, usar verify-token para nuevas implementaciones)
    /// </summary>
    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyTokenRequest request)
    {
        try
        {
            var result = await _authService.VerifyEmailAsync(request);
            return Ok(new { message = "Email verificado exitosamente", verified = result });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    /// <summary>
    /// Reenvía el código de verificación
    /// </summary>
    [HttpPost("resend-verification")]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationRequest request)
    {
        try
        {
            var result = await _authService.ResendVerificationCodeAsync(request.Email);
            return Ok(new { message = "Código de verificación enviado", sent = result });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region Prevalidación

    /// <summary>
    /// Prevalida un email para saber qué métodos de login están disponibles
    /// </summary>
    [HttpPost("prevalidate")]
    public async Task<IActionResult> PrevalidateEmail([FromBody] PrevalidateRequest request)
    {
        try
        {
            var result = await _authService.PrevalidateEmailAsync(request.Email);
            return Ok(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region Verificación Genérica

    /// <summary>
    /// Verifica cualquier tipo de token (email_verification, otp, magic_link, password_reset)
    /// </summary>
    [HttpPost("verify-token")]
    public async Task<IActionResult> VerifyToken([FromBody] VerifyGenericTokenRequest request)
    {
        try
        {
            var result = await _authService.VerifyGenericTokenAsync(request);
            return Ok(new { message = "Token verificado exitosamente", verified = result });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region Login con Password

    /// <summary>
    /// Login tradicional con email y contraseña (legacy)
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var tokenResponse = await _authService.LoginAsync(request);
            return Ok(tokenResponse);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    /// <summary>
    /// Login con email y contraseña (nuevo endpoint específico)
    /// </summary>
    [HttpPost("login/password")]
    public async Task<IActionResult> LoginWithPassword([FromBody] LoginPasswordRequest request)
    {
        try
        {
            var tokenResponse = await _authService.LoginWithPasswordAsync(request);
            return Ok(tokenResponse);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region Login con OTP

    /// <summary>
    /// Solicita un código OTP después de validar la contraseña
    /// </summary>
    [HttpPost("login/password-request-otp")]
    public async Task<IActionResult> RequestLoginOtp([FromBody] LoginPasswordRequestOtpRequest request)
    {
        try
        {
            var result = await _authService.RequestLoginOtpAsync(request);
            return Ok(new { message = "Código OTP enviado a tu email", sent = result });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    /// <summary>
    /// Login con código OTP
    /// </summary>
    [HttpPost("login/otp")]
    public async Task<IActionResult> LoginWithOtp([FromBody] LoginOtpRequest request)
    {
        try
        {
            var tokenResponse = await _authService.LoginWithOtpAsync(request);
            return Ok(tokenResponse);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region Magic Link

    /// <summary>
    /// Solicita un magic link para login sin contraseña
    /// </summary>
    [HttpPost("login/magic-request")]
    public async Task<IActionResult> RequestMagicLink([FromBody] MagicLinkRequestRequest request)
    {
        try
        {
            var result = await _authService.RequestMagicLinkAsync(request.Email);
            return Ok(new { message = "Magic link enviado a tu email", sent = result });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    /// <summary>
    /// Login usando un magic link
    /// </summary>
    [HttpPost("login/magic")]
    public async Task<IActionResult> LoginWithMagicLink([FromBody] MagicLinkLoginRequest request)
    {
        try
        {
            var tokenResponse = await _authService.LoginWithMagicLinkAsync(request.Token);
            return Ok(tokenResponse);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region OAuth

    /// <summary>
    /// Autenticación con Google OAuth
    /// </summary>
    [HttpPost("oauth/google")]
    public async Task<IActionResult> GoogleOAuth([FromBody] GoogleOAuthRequest request)
    {
        try
        {
            var response = await _authService.AuthenticateWithGoogleAsync(request.IdToken);
            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region Password Reset

    /// <summary>
    /// Solicita un token para resetear la contraseña
    /// </summary>
    [HttpPost("request-reset")]
    public async Task<IActionResult> RequestPasswordReset([FromBody] RequestPasswordResetRequest request)
    {
        try
        {
            var result = await _authService.RequestPasswordResetAsync(request.Email);
            return Ok(new { message = "Si el email existe, se enviará un enlace de recuperación", sent = result });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    /// <summary>
    /// Resetea la contraseña usando el token recibido
    /// </summary>
    [HttpPost("reset")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        try
        {
            var result = await _authService.ResetPasswordAsync(request);
            return Ok(new { message = "Contraseña restablecida exitosamente", success = result });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion

    #region Token Management

    /// <summary>
    /// Renueva el access token usando un refresh token
    /// </summary>
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var tokenResponse = await _authService.RefreshTokenAsync(request.RefreshToken);
            return Ok(tokenResponse);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    /// <summary>
    /// Revoca un refresh token (logout)
    /// </summary>
    [HttpPost("revoke-token")]
    [Authorize]
    public async Task<IActionResult> RevokeToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            await _authService.RevokeTokenAsync(request.RefreshToken);
            return Ok(new { message = "Token revocado exitosamente" });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    #endregion
}

public class RefreshTokenRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}

public class ResendVerificationRequest
{
    public string Email { get; set; } = string.Empty;
}