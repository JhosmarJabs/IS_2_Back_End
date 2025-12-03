using IS_2_Back_End.Attributes;
using IS_2_Back_End.Document;
using System.Security.Cryptography;

namespace IS_2_Back_End.Middlewares;

/// <summary>
/// Middleware para protección contra CSRF (Cross-Site Request Forgery)
/// REQ-017: Protección contra CSRF con tokens en peticiones state-changing
/// </summary>
[Requirement(Requirements.CSRF_PROTECTION, "Implementación de protección CSRF con tokens")]
public class CsrfProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private const string CsrfTokenHeader = "X-CSRF-Token";
    private const string CsrfTokenCookie = "CSRF-TOKEN";

    // Métodos que requieren protección CSRF
    private static readonly string[] ProtectedMethods = { "POST", "PUT", "DELETE", "PATCH" };

    // Rutas excluidas de validación CSRF (APIs públicas)
    private static readonly string[] ExcludedPaths =
    {
        "/api/auth/register",
        "/api/auth/login",
        "/api/auth/refresh-token",
        "/swagger"
    };

    public CsrfProtectionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value?.ToLower() ?? "";
        var method = context.Request.Method.ToUpper();

        // Generar y enviar token CSRF para peticiones GET
        if (method == "GET" && !path.Contains("swagger"))
        {
            GenerateAndSetCsrfToken(context);
        }

        // Validar token CSRF para métodos protegidos
        if (ProtectedMethods.Contains(method) && !IsExcludedPath(path))
        {
            if (!ValidateCsrfToken(context))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsJsonAsync(new
                {
                    message = "Token CSRF inválido o ausente. Por favor, recarga la página.",
                    error = "CSRF_VALIDATION_FAILED"
                });
                return;
            }
        }

        await _next(context);
    }

    private void GenerateAndSetCsrfToken(HttpContext context)
    {
        // Verificar si ya existe un token válido
        if (context.Request.Cookies.TryGetValue(CsrfTokenCookie, out var existingToken)
            && !string.IsNullOrEmpty(existingToken))
        {
            return; // Token ya existe
        }

        // Generar nuevo token
        var token = GenerateSecureToken();

        // Establecer cookie con token
        context.Response.Cookies.Append(CsrfTokenCookie, token, new CookieOptions
        {
            HttpOnly = false, // JavaScript necesita leer este cookie
            Secure = true,
            SameSite = SameSiteMode.Strict,
            MaxAge = TimeSpan.FromHours(2)
        });

        // También enviar en header para SPA
        context.Response.Headers.Append(CsrfTokenHeader, token);
    }

    private bool ValidateCsrfToken(HttpContext context)
    {
        // Obtener token de cookie
        if (!context.Request.Cookies.TryGetValue(CsrfTokenCookie, out var cookieToken))
        {
            return false;
        }

        // Obtener token de header
        if (!context.Request.Headers.TryGetValue(CsrfTokenHeader, out var headerToken))
        {
            return false;
        }

        // Validar que ambos tokens coincidan
        return !string.IsNullOrEmpty(cookieToken)
            && !string.IsNullOrEmpty(headerToken)
            && cookieToken == headerToken.ToString();
    }

    private bool IsExcludedPath(string path)
    {
        return ExcludedPaths.Any(excluded => path.StartsWith(excluded));
    }

    private string GenerateSecureToken()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}