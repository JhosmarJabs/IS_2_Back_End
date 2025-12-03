using System.Diagnostics;
using System.Text;

namespace IS_2_Back_End.Helpers;

/// <summary>
/// Logger detallado que incluye contexto de la capa (Service, Repository, etc.)
/// </summary>
public interface IDetailedLogger
{
    void LogMethodEntry(string className, string methodName, object? parameters = null);
    void LogMethodExit(string className, string methodName, long durationMs, object? result = null);
    void LogMethodError(string className, string methodName, Exception exception, long durationMs);
    void LogDatabaseQuery(string query, object? parameters = null);
    void LogBusinessLogic(string message, object? context = null);
}

public class DetailedLogger : IDetailedLogger
{
    private readonly ILogger<DetailedLogger> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public DetailedLogger(ILogger<DetailedLogger> logger, IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public void LogMethodEntry(string className, string methodName, object? parameters = null)
    {
        var correlationId = GetCorrelationId();
        var logMessage = new StringBuilder();

        logMessage.AppendLine($"║ [{correlationId}] ▶️  [{className}] {methodName} - START");

        if (parameters != null)
        {
            var sanitizedParams = SanitizeObject(parameters);
            logMessage.AppendLine($"║    Parameters: {sanitizedParams}");
        }

        _logger.LogDebug(logMessage.ToString());
    }

    public void LogMethodExit(string className, string methodName, long durationMs, object? result = null)
    {
        var correlationId = GetCorrelationId();
        var emoji = durationMs > 1000 ? "🐌" : durationMs > 500 ? "⚠️" : "✅";

        var logMessage = new StringBuilder();
        logMessage.AppendLine($"║ [{correlationId}] {emoji} [{className}] {methodName} - SUCCESS ({durationMs}ms)");

        if (result != null && durationMs > 500)
        {
            logMessage.AppendLine($"║    ⚠️  SLOW OPERATION - Consider optimization");
        }

        _logger.LogDebug(logMessage.ToString());
    }

    public void LogMethodError(string className, string methodName, Exception exception, long durationMs)
    {
        var correlationId = GetCorrelationId();

        var logMessage = new StringBuilder();
        logMessage.AppendLine($"║ [{correlationId}] ❌ [{className}] {methodName} - ERROR ({durationMs}ms)");
        logMessage.AppendLine($"║    Exception: {exception.GetType().Name}");
        logMessage.AppendLine($"║    Message: {exception.Message}");

        // Mostrar línea específica del error
        var stackTrace = exception.StackTrace?.Split('\n').FirstOrDefault(line => line.Contains(className));
        if (stackTrace != null)
        {
            logMessage.AppendLine($"║    Location: {stackTrace.Trim()}");
        }

        _logger.LogError(logMessage.ToString());
    }

    public void LogDatabaseQuery(string query, object? parameters = null)
    {
        var correlationId = GetCorrelationId();

        var logMessage = new StringBuilder();
        logMessage.AppendLine($"║ [{correlationId}] 🗄️  DATABASE QUERY");
        logMessage.AppendLine($"║    SQL: {TruncateQuery(query)}");

        if (parameters != null)
        {
            logMessage.AppendLine($"║    Params: {SanitizeObject(parameters)}");
        }

        _logger.LogDebug(logMessage.ToString());
    }

    public void LogBusinessLogic(string message, object? context = null)
    {
        var correlationId = GetCorrelationId();

        var logMessage = new StringBuilder();
        logMessage.AppendLine($"║ [{correlationId}] 💼 BUSINESS LOGIC: {message}");

        if (context != null)
        {
            logMessage.AppendLine($"║    Context: {SanitizeObject(context)}");
        }

        _logger.LogInformation(logMessage.ToString());
    }

    #region Helper Methods

    private string GetCorrelationId()
    {
        try
        {
            return _httpContextAccessor.HttpContext?.Items["CorrelationId"]?.ToString() ?? "N/A";
        }
        catch
        {
            return "N/A";
        }
    }

    private string SanitizeObject(object obj)
    {
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(obj);

            // Redactar campos sensibles
            var sensitiveFields = new[] { "password", "token", "secret", "authorization" };
            foreach (var field in sensitiveFields)
            {
                json = System.Text.RegularExpressions.Regex.Replace(
                    json,
                    $"\"{field}\"\\s*:\\s*\"[^\"]*\"",
                    $"\"{field}\":\"[REDACTED]\"",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase
                );
            }

            return json.Length > 200 ? json[..200] + "..." : json;
        }
        catch
        {
            return obj.ToString() ?? "null";
        }
    }

    private string TruncateQuery(string query)
    {
        var cleaned = query.Trim().Replace("\n", " ").Replace("\r", "");
        return cleaned.Length > 150 ? cleaned[..150] + "..." : cleaned;
    }

    #endregion
}

/// <summary>
/// Extension methods para facilitar el logging con DetailedLogger
/// </summary>
public static class DetailedLoggerExtensions
{
    /// <summary>
    /// Ejecuta un método con logging automático de entrada, salida y errores
    /// </summary>
    public static async Task<T> ExecuteWithLoggingAsync<T>(
        this IDetailedLogger logger,
        string className,
        string methodName,
        Func<Task<T>> operation,
        object? parameters = null)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            logger.LogMethodEntry(className, methodName, parameters);
            var result = await operation();
            stopwatch.Stop();
            logger.LogMethodExit(className, methodName, stopwatch.ElapsedMilliseconds, result);
            return result;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            logger.LogMethodError(className, methodName, ex, stopwatch.ElapsedMilliseconds);
            throw;
        }
    }

    /// <summary>
    /// Versión síncrona de ExecuteWithLogging
    /// </summary>
    public static T ExecuteWithLogging<T>(
        this IDetailedLogger logger,
        string className,
        string methodName,
        Func<T> operation,
        object? parameters = null)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            logger.LogMethodEntry(className, methodName, parameters);
            var result = operation();
            stopwatch.Stop();
            logger.LogMethodExit(className, methodName, stopwatch.ElapsedMilliseconds, result);
            return result;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            logger.LogMethodError(className, methodName, ex, stopwatch.ElapsedMilliseconds);
            throw;
        }
    }
}