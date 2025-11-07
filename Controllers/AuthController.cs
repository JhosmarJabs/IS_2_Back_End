using IS_2_Back_End.DTOs.Auth;
using IS_2_Back_End.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IS_2_Back_End.Controllers;

/// <summary>
/// Controlador de autenticación y manejo de usuarios
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// Registra un nuevo usuario en el sistema
    /// </summary>
    /// <param name="request">Datos del usuario a registrar</param>
    /// <returns>Usuario creado con información básica</returns>
    /// <response code="200">Usuario registrado exitosamente</response>
    /// <response code="400">Datos inválidos o email ya registrado</response>
    /// <response code="500">Error interno del servidor</response>
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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
    /// Inicia sesión con email y contraseña
    /// </summary>
    /// <param name="request">Credenciales de acceso</param>
    /// <returns>Access token y refresh token</returns>
    /// <response code="200">Login exitoso, tokens generados</response>
    /// <response code="401">Credenciales inválidas o email no verificado</response>
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
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
    /// Verifica el email del usuario con el código OTP recibido
    /// </summary>
    /// <param name="request">Email y código de verificación</param>
    /// <returns>Confirmación de verificación</returns>
    /// <response code="200">Email verificado exitosamente</response>
    /// <response code="400">Token inválido o expirado</response>
    [HttpPost("verify-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
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
    /// Renueva el access token usando un refresh token válido
    /// </summary>
    /// <param name="request">Refresh token actual</param>
    /// <returns>Nuevo par de tokens (access y refresh)</returns>
    /// <response code="200">Tokens renovados exitosamente</response>
    /// <response code="401">Refresh token inválido o expirado</response>
    [HttpPost("refresh-token")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
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
    /// Reenvía el código de verificación al email del usuario
    /// </summary>
    /// <param name="request">Email del usuario</param>
    /// <returns>Confirmación de envío</returns>
    /// <response code="200">Código enviado exitosamente</response>
    /// <response code="400">Usuario no encontrado o email ya verificado</response>
    [HttpPost("resend-verification")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
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

    /// <summary>
    /// Revoca un refresh token (logout)
    /// </summary>
    /// <param name="request">Refresh token a revocar</param>
    /// <returns>Confirmación de revocación</returns>
    /// <response code="200">Token revocado exitosamente</response>
    /// <response code="401">No autorizado</response>
    [HttpPost("revoke-token")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
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
}

/// <summary>
/// Request para refresh token
/// </summary>
public class RefreshTokenRequest
{
    /// <summary>
    /// Refresh token recibido en el login
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;
}

/// <summary>
/// Request para reenviar verificación
/// </summary>
public class ResendVerificationRequest
{
    /// <summary>
    /// Email del usuario
    /// </summary>
    public string Email { get; set; } = string.Empty;
}