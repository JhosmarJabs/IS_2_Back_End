using System.Collections.Concurrent;

namespace IS_2_Back_End.Middlewares;

/// <summary>
/// Middleware para limitar intentos de login y recuperación de contraseña
/// </summary>
public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private static readonly ConcurrentDictionary<string, LoginAttempt> _loginAttempts = new();
    private static readonly ConcurrentDictionary<string, RecoveryAttempt> _recoveryAttempts = new();
    
    // Configuración
    private const int MAX_LOGIN_ATTEMPTS = 5;
    private const int LOGIN_LOCKOUT_MINUTES = 15;
    private const int MAX_RECOVERY_ATTEMPTS = 3;
    private const int RECOVERY_LOCKOUT_MINUTES = 30;

    public RateLimitingMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value?.ToLower();
        var ipAddress = GetClientIpAddress(context);

        // Limpiar intentos expirados cada cierto tiempo
        CleanupExpiredAttempts();

        // Verificar límites según el endpoint
        if (path?.Contains("/api/auth/login") == true || 
            path?.Contains("/api/auth/login/password") == true)
        {
            if (IsLoginBlocked(ipAddress))
            {
                context.Response.StatusCode = 429; // Too Many Requests
                await context.Response.WriteAsJsonAsync(new
                {
                    message = $"Demasiados intentos de inicio de sesión. Intenta nuevamente en {LOGIN_LOCKOUT_MINUTES} minutos.",
                    retryAfter = GetLoginRetryAfter(ipAddress)
                });
                return;
            }
        }
        else if (path?.Contains("/api/auth/request-reset") == true)
        {
            if (IsRecoveryBlocked(ipAddress))
            {
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new
                {
                    message = $"Demasiados intentos de recuperación. Intenta nuevamente en {RECOVERY_LOCKOUT_MINUTES} minutos.",
                    retryAfter = GetRecoveryRetryAfter(ipAddress)
                });
                return;
            }
        }

        await _next(context);

        // Registrar intento fallido después de la respuesta
        if (context.Response.StatusCode == 401 && path?.Contains("/login") == true)
        {
            RecordFailedLogin(ipAddress);
        }
        else if (context.Response.StatusCode == 200 && path?.Contains("/login") == true)
        {
            ClearLoginAttempts(ipAddress);
        }

        if (path?.Contains("/request-reset") == true)
        {
            RecordRecoveryAttempt(ipAddress);
        }
    }

    private string GetClientIpAddress(HttpContext context)
    {
        // Intentar obtener IP real detrás de proxy
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }

        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private bool IsLoginBlocked(string ipAddress)
    {
        if (!_loginAttempts.TryGetValue(ipAddress, out var attempt))
            return false;

        if (DateTime.UtcNow > attempt.LockedUntil)
        {
            _loginAttempts.TryRemove(ipAddress, out _);
            return false;
        }

        return attempt.Attempts >= MAX_LOGIN_ATTEMPTS;
    }

    private bool IsRecoveryBlocked(string ipAddress)
    {
        if (!_recoveryAttempts.TryGetValue(ipAddress, out var attempt))
            return false;

        if (DateTime.UtcNow > attempt.LockedUntil)
        {
            _recoveryAttempts.TryRemove(ipAddress, out _);
            return false;
        }

        return attempt.Attempts >= MAX_RECOVERY_ATTEMPTS;
    }

    private void RecordFailedLogin(string ipAddress)
    {
        _loginAttempts.AddOrUpdate(ipAddress,
            new LoginAttempt
            {
                Attempts = 1,
                FirstAttempt = DateTime.UtcNow,
                LockedUntil = DateTime.UtcNow.AddMinutes(LOGIN_LOCKOUT_MINUTES)
            },
            (key, existing) =>
            {
                existing.Attempts++;
                if (existing.Attempts >= MAX_LOGIN_ATTEMPTS)
                {
                    existing.LockedUntil = DateTime.UtcNow.AddMinutes(LOGIN_LOCKOUT_MINUTES);
                }
                return existing;
            });
    }

    private void RecordRecoveryAttempt(string ipAddress)
    {
        _recoveryAttempts.AddOrUpdate(ipAddress,
            new RecoveryAttempt
            {
                Attempts = 1,
                FirstAttempt = DateTime.UtcNow,
                LockedUntil = DateTime.UtcNow.AddMinutes(RECOVERY_LOCKOUT_MINUTES)
            },
            (key, existing) =>
            {
                existing.Attempts++;
                if (existing.Attempts >= MAX_RECOVERY_ATTEMPTS)
                {
                    existing.LockedUntil = DateTime.UtcNow.AddMinutes(RECOVERY_LOCKOUT_MINUTES);
                }
                return existing;
            });
    }

    private void ClearLoginAttempts(string ipAddress)
    {
        _loginAttempts.TryRemove(ipAddress, out _);
    }

    private int GetLoginRetryAfter(string ipAddress)
    {
        if (_loginAttempts.TryGetValue(ipAddress, out var attempt))
        {
            var remaining = (attempt.LockedUntil - DateTime.UtcNow).TotalSeconds;
            return (int)Math.Max(0, remaining);
        }
        return 0;
    }

    private int GetRecoveryRetryAfter(string ipAddress)
    {
        if (_recoveryAttempts.TryGetValue(ipAddress, out var attempt))
        {
            var remaining = (attempt.LockedUntil - DateTime.UtcNow).TotalSeconds;
            return (int)Math.Max(0, remaining);
        }
        return 0;
    }

    private void CleanupExpiredAttempts()
    {
        var now = DateTime.UtcNow;

        // Limpiar intentos de login expirados
        foreach (var kvp in _loginAttempts.Where(x => now > x.Value.LockedUntil.AddHours(1)))
        {
            _loginAttempts.TryRemove(kvp.Key, out _);
        }

        // Limpiar intentos de recovery expirados
        foreach (var kvp in _recoveryAttempts.Where(x => now > x.Value.LockedUntil.AddHours(1)))
        {
            _recoveryAttempts.TryRemove(kvp.Key, out _);
        }
    }

    private class LoginAttempt
    {
        public int Attempts { get; set; }
        public DateTime FirstAttempt { get; set; }
        public DateTime LockedUntil { get; set; }
    }

    private class RecoveryAttempt
    {
        public int Attempts { get; set; }
        public DateTime FirstAttempt { get; set; }
        public DateTime LockedUntil { get; set; }
    }
}