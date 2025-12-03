using IS_2_Back_End.DTOs.Auth;
using IS_2_Back_End.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IS_2_Back_End.Controllers;

[ApiController]
[Route("api/mfa")]
[Authorize]
public class MfaController : ControllerBase
{
    private readonly IMfaService _mfaService;

    public MfaController(IMfaService mfaService)
    {
        _mfaService = mfaService;
    }

    /// <summary>
    /// Iniciar configuración de MFA - Genera QR code
    /// </summary>
    [HttpPost("setup")]
    public async Task<IActionResult> SetupMfa()
    {
        try
        {
            var userId = GetCurrentUserId();
            var qrCodeUrl = await _mfaService.GenerateMfaSecretAsync(userId);

            return Ok(new MfaSetupResponse
            {
                QrCodeUrl = qrCodeUrl,
                Secret = ExtractSecretFromUrl(qrCodeUrl)
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error al configurar MFA", error = ex.Message });
        }
    }

    /// <summary>
    /// Habilitar MFA después de verificar código
    /// </summary>
    [HttpPost("enable")]
    public async Task<IActionResult> EnableMfa([FromBody] MfaEnableRequest request)
    {
        try
        {
            var userId = GetCurrentUserId();
            var result = await _mfaService.EnableMfaAsync(userId, request.VerificationCode);

            return Ok(new
            {
                message = "MFA habilitado exitosamente",
                enabled = result
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error al habilitar MFA", error = ex.Message });
        }
    }

    /// <summary>
    /// Deshabilitar MFA
    /// </summary>
    [HttpPost("disable")]
    public async Task<IActionResult> DisableMfa([FromBody] MfaDisableRequest request)
    {
        try
        {
            var userId = GetCurrentUserId();
            var result = await _mfaService.DisableMfaAsync(userId, request.VerificationCode);

            return Ok(new
            {
                message = "MFA deshabilitado exitosamente",
                disabled = result
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error al deshabilitar MFA", error = ex.Message });
        }
    }

    /// <summary>
    /// Generar códigos de respaldo
    /// </summary>
    [HttpPost("backup-codes")]
    public async Task<IActionResult> GenerateBackupCodes()
    {
        try
        {
            var userId = GetCurrentUserId();
            var codes = await _mfaService.GenerateBackupCodesAsync(userId);

            return Ok(new BackupCodesResponse
            {
                Codes = codes
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error al generar códigos de respaldo", error = ex.Message });
        }
    }

    /// <summary>
    /// Verificar código MFA (para testing)
    /// </summary>
    [HttpPost("verify")]
    public async Task<IActionResult> VerifyMfa([FromBody] MfaVerifyRequest request)
    {
        try
        {
            var userId = GetCurrentUserId();
            var isValid = await _mfaService.VerifyMfaCodeAsync(userId, request.Code);

            if (!isValid)
            {
                return BadRequest(new { message = "Código MFA inválido" });
            }

            return Ok(new { message = "Código MFA válido", verified = true });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error al verificar MFA", error = ex.Message });
        }
    }

    #region Helper Methods

    private int GetCurrentUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim))
        {
            throw new UnauthorizedAccessException("Usuario no autenticado");
        }
        return int.Parse(userIdClaim);
    }

    private string ExtractSecretFromUrl(string url)
    {
        var secretParam = "secret=";
        var startIndex = url.IndexOf(secretParam);
        if (startIndex == -1) return "";

        startIndex += secretParam.Length;
        var endIndex = url.IndexOf("&", startIndex);

        if (endIndex == -1)
            return url[startIndex..];

        return url[startIndex..endIndex];
    }

    #endregion
}