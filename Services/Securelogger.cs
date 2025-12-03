using IS_2_Back_End.Attributes;
using IS_2_Back_End.Document;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IS_2_Back_End.Services;

/// <summary>
/// Servicio de logging seguro que previene la exposición de datos sensibles
/// REQ-023: Los logs no deben contener datos sensibles
/// </summary>
//[Requirement(Requirements.SECURE_LOGGING, "Implementación de logging seguro sin datos sensibles")]
public interface ISecureLogger
{
    void LogInfo(string message, object? data = null);
    void LogWarning(string message, object? data = null);
    void LogError(string message, Exception? exception = null, object? data = null);
    void LogSecurityEvent(string eventType, string description, object? metadata = null);
}

public class SecureLogger : ISecureLogger
{
    private readonly ILogger<SecureLogger> _logger;

    // Patrones de datos sensibles a redactar
    private static readonly string[] SensitivePatterns = new[]
    {
        @"password\s*[=:]\s*[^\s,}\]]+",
        @"token\s*[=:]\s*[^\s,}\]]+",
        @"secret\s*[=:]\s*[^\s,}\]]+",
        @"api[_-]?key\s*[=:]\s*[^\s,}\]]+",
        @"authorization\s*[=:]\s*[^\s,}\]]+",
        @"bearer\s+[^\s,}\]]+",
        @"\b\d{16}\b", // Números de tarjeta
        @"\b\d{3}-\d{2}-\d{4}\b", // SSN
        @"salt\s*[=:]\s*[^\s,}\]]+",
        @"passwordHash\s*[=:]\s*[^\s,}\]]+",
    };

    // Campos sensibles en objetos
    private static readonly string[] SensitiveFields = new[]
    {
        "password", "passwordhash", "salt", "token", "secret",
        "apikey", "refreshtoken", "accesstoken", "creditcard",
        "ssn", "authorization", "bearer"
    };

    public SecureLogger(ILogger<SecureLogger> logger)
    {
        _logger = logger;
    }

    public void LogInfo(string message, object? data = null)
    {
        var sanitizedMessage = SanitizeMessage(message);
        var sanitizedData = SanitizeData(data);

        _logger.LogInformation("{Message} {Data}",
            sanitizedMessage,
            sanitizedData != null ? JsonSerializer.Serialize(sanitizedData) : "");
    }

    public void LogWarning(string message, object? data = null)
    {
        var sanitizedMessage = SanitizeMessage(message);
        var sanitizedData = SanitizeData(data);

        _logger.LogWarning("{Message} {Data}",
            sanitizedMessage,
            sanitizedData != null ? JsonSerializer.Serialize(sanitizedData) : "");
    }

    public void LogError(string message, Exception? exception = null, object? data = null)
    {
        var sanitizedMessage = SanitizeMessage(message);
        var sanitizedData = SanitizeData(data);
        var sanitizedException = exception != null ? SanitizeException(exception) : null;

        _logger.LogError(sanitizedException, "{Message} {Data}",
            sanitizedMessage,
            sanitizedData != null ? JsonSerializer.Serialize(sanitizedData) : "");
    }

    public void LogSecurityEvent(string eventType, string description, object? metadata = null)
    {
        var sanitizedDescription = SanitizeMessage(description);
        var sanitizedMetadata = SanitizeData(metadata);

        _logger.LogWarning("[SECURITY EVENT] {EventType}: {Description} {Metadata}",
            eventType,
            sanitizedDescription,
            sanitizedMetadata != null ? JsonSerializer.Serialize(sanitizedMetadata) : "");
    }

    #region Sanitization Methods

    private string SanitizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message))
            return message;

        var sanitized = message;

        // Redactar patrones sensibles
        foreach (var pattern in SensitivePatterns)
        {
            sanitized = Regex.Replace(sanitized, pattern,
                match => RedactMatch(match.Value),
                RegexOptions.IgnoreCase);
        }

        return sanitized;
    }

    private object? SanitizeData(object? data)
    {
        if (data == null)
            return null;

        try
        {
            // Serializar y deserializar para obtener un diccionario
            var json = JsonSerializer.Serialize(data);
            var dict = JsonSerializer.Deserialize<Dictionary<string, object>>(json);

            if (dict == null)
                return data;

            return RedactSensitiveFields(dict);
        }
        catch
        {
            // Si falla la serialización, redactar como string
            return SanitizeMessage(data.ToString() ?? "");
        }
    }

    private Dictionary<string, object> RedactSensitiveFields(Dictionary<string, object> dict)
    {
        var sanitized = new Dictionary<string, object>();

        foreach (var kvp in dict)
        {
            var key = kvp.Key.ToLower();

            if (SensitiveFields.Any(field => key.Contains(field)))
            {
                sanitized[kvp.Key] = "[REDACTED]";
            }
            else if (kvp.Value is Dictionary<string, object> nestedDict)
            {
                sanitized[kvp.Key] = RedactSensitiveFields(nestedDict);
            }
            else if (kvp.Value is string strValue)
            {
                sanitized[kvp.Key] = SanitizeMessage(strValue);
            }
            else
            {
                sanitized[kvp.Key] = kvp.Value;
            }
        }

        return sanitized;
    }

    private string RedactMatch(string match)
    {
        var parts = match.Split(new[] { '=', ':' }, 2);
        if (parts.Length == 2)
        {
            return $"{parts[0]}=[REDACTED]";
        }
        return "[REDACTED]";
    }

    private Exception SanitizeException(Exception exception)
    {
        var message = SanitizeMessage(exception.Message);
        var sanitizedException = new Exception(message,
            exception.InnerException != null ? SanitizeException(exception.InnerException) : null);

        return sanitizedException;
    }

    #endregion
}