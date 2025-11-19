namespace IS_2_Back_End.Middlewares;

/// <summary>
/// Middleware para agregar headers de seguridad HTTP
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Content Security Policy - Previene XSS
        context.Response.Headers.Append("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' data:; " +
            "connect-src 'self' https://is-2-front-end.vercel.app; " +
            "frame-ancestors 'none'");

        // Strict-Transport-Security - Fuerza HTTPS
        context.Response.Headers.Append("Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload");

        // X-Frame-Options - Previene clickjacking
        context.Response.Headers.Append("X-Frame-Options", "DENY");

        // X-Content-Type-Options - Previene MIME sniffing
        context.Response.Headers.Append("X-Content-Type-Options", "nosniff");

        // X-XSS-Protection - Protección XSS en navegadores antiguos
        context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");

        // Referrer-Policy - Controla información de referrer
        context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");

        // Permissions-Policy - Controla APIs del navegador
        context.Response.Headers.Append("Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()");

        // Remover headers que exponen información del servidor
        context.Response.Headers.Remove("Server");
        context.Response.Headers.Remove("X-Powered-By");
        context.Response.Headers.Remove("X-AspNet-Version");

        await _next(context);
    }
}