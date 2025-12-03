using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace IS_2_Back_End.Middlewares;

/// <summary>
/// Middleware que registra cada request y response con detalles completos
/// </summary>
public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Generar Correlation ID único para este request
        var correlationId = Guid.NewGuid().ToString("N")[..8].ToUpper();
        context.Items["CorrelationId"] = correlationId;

        // Capturar request body
        context.Request.EnableBuffering();
        var requestBody = await ReadRequestBodyAsync(context.Request);

        // Iniciar timer
        var stopwatch = Stopwatch.StartNew();

        // Log de INICIO del request
        LogRequestStart(context, correlationId, requestBody);

        // Capturar response body
        var originalBodyStream = context.Response.Body;
        using var responseBody = new MemoryStream();
        context.Response.Body = responseBody;

        try
        {
            // Continuar con el pipeline
            await _next(context);

            stopwatch.Stop();

            // Capturar response body
            var responseBodyText = await ReadResponseBodyAsync(responseBody);

            // Log de FIN del request (exitoso)
            LogRequestEnd(context, correlationId, stopwatch.ElapsedMilliseconds, responseBodyText);

            // Copiar response body al stream original
            await responseBody.CopyToAsync(originalBodyStream);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();

            // Log de ERROR
            LogRequestError(context, correlationId, stopwatch.ElapsedMilliseconds, ex);

            // Re-throw para que sea manejado por ExceptionHandlingMiddleware
            throw;
        }
        finally
        {
            context.Response.Body = originalBodyStream;
        }
    }

    #region Log Methods

    private void LogRequestStart(HttpContext context, string correlationId, string requestBody)
    {
        var request = context.Request;
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        var logMessage = new StringBuilder();
        logMessage.AppendLine($"\n╔══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ 🔵 REQUEST START [{correlationId}]");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ Method:    {request.Method}");
        logMessage.AppendLine($"║ Path:      {request.Path}{request.QueryString}");
        logMessage.AppendLine($"║ IP:        {ip}");
        logMessage.AppendLine($"║ Time:      {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}");

        // Headers importantes
        if (request.Headers.ContainsKey("Authorization"))
        {
            var auth = request.Headers["Authorization"].ToString();
            logMessage.AppendLine($"║ Auth:      {(auth.Length > 20 ? auth[..20] + "..." : auth)}");
        }

        if (request.Headers.ContainsKey("Content-Type"))
        {
            logMessage.AppendLine($"║ Content:   {request.Headers["Content-Type"]}");
        }

        // Request body (sanitizado)
        if (!string.IsNullOrWhiteSpace(requestBody))
        {
            var sanitizedBody = SanitizeRequestBody(requestBody);
            logMessage.AppendLine($"║ Body:      {sanitizedBody}");
        }

        logMessage.AppendLine($"╚══════════════════════════════════════════════════════════════════════════════");

        _logger.LogInformation(logMessage.ToString());
    }

    private void LogRequestEnd(HttpContext context, string correlationId, long duration, string responseBody)
    {
        var statusCode = context.Response.StatusCode;
        var isSuccess = statusCode >= 200 && statusCode < 300;
        var emoji = isSuccess ? "✅" : "⚠️";

        var logMessage = new StringBuilder();
        logMessage.AppendLine($"\n╔══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ {emoji} REQUEST END [{correlationId}]");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ Status:    {statusCode} {GetStatusCodeName(statusCode)}");
        logMessage.AppendLine($"║ Duration:  {duration}ms");
        logMessage.AppendLine($"║ Time:      {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}");

        // Si hay error, mostrar response body
        if (!isSuccess && !string.IsNullOrWhiteSpace(responseBody))
        {
            var truncatedBody = responseBody.Length > 500 ? responseBody[..500] + "..." : responseBody;
            logMessage.AppendLine($"║ Response:  {truncatedBody}");
        }

        logMessage.AppendLine($"╚══════════════════════════════════════════════════════════════════════════════");

        if (isSuccess)
        {
            _logger.LogInformation(logMessage.ToString());
        }
        else
        {
            _logger.LogWarning(logMessage.ToString());
        }
    }

    private void LogRequestError(HttpContext context, string correlationId, long duration, Exception exception)
    {
        var logMessage = new StringBuilder();
        logMessage.AppendLine($"\n╔══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ ❌ REQUEST ERROR [{correlationId}]");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ Method:      {context.Request.Method} {context.Request.Path}");
        logMessage.AppendLine($"║ Duration:    {duration}ms");
        logMessage.AppendLine($"║ Exception:   {exception.GetType().Name}");
        logMessage.AppendLine($"║ Message:     {exception.Message}");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ STACK TRACE:");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");

        // Stack trace formateado
        var stackLines = exception.StackTrace?.Split('\n') ?? Array.Empty<string>();
        foreach (var line in stackLines.Take(10)) // Primeras 10 líneas
        {
            logMessage.AppendLine($"║ {line.Trim()}");
        }

        // Inner exception
        if (exception.InnerException != null)
        {
            logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
            logMessage.AppendLine($"║ INNER EXCEPTION: {exception.InnerException.GetType().Name}");
            logMessage.AppendLine($"║ Message: {exception.InnerException.Message}");
        }

        logMessage.AppendLine($"╚══════════════════════════════════════════════════════════════════════════════");

        _logger.LogError(logMessage.ToString());
    }

    #endregion

    #region Helper Methods

    private async Task<string> ReadRequestBodyAsync(HttpRequest request)
    {
        try
        {
            request.Body.Position = 0;
            using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            request.Body.Position = 0;
            return body;
        }
        catch
        {
            return string.Empty;
        }
    }

    private async Task<string> ReadResponseBodyAsync(MemoryStream responseBody)
    {
        try
        {
            responseBody.Position = 0;
            using var reader = new StreamReader(responseBody, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            responseBody.Position = 0;
            return body;
        }
        catch
        {
            return string.Empty;
        }
    }

    private string SanitizeRequestBody(string body)
    {
        try
        {
            // Parsear JSON y redactar campos sensibles
            var jsonDoc = JsonDocument.Parse(body);
            var sanitized = SanitizeJsonElement(jsonDoc.RootElement);
            return JsonSerializer.Serialize(sanitized, new JsonSerializerOptions { WriteIndented = false });
        }
        catch
        {
            // Si no es JSON válido, truncar
            return body.Length > 200 ? body[..200] + "..." : body;
        }
    }

    private object SanitizeJsonElement(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var obj = new Dictionary<string, object>();
                foreach (var prop in element.EnumerateObject())
                {
                    var key = prop.Name.ToLower();
                    // Redactar campos sensibles
                    if (key.Contains("password") || key.Contains("token") || key.Contains("secret"))
                    {
                        obj[prop.Name] = "[REDACTED]";
                    }
                    else
                    {
                        obj[prop.Name] = SanitizeJsonElement(prop.Value);
                    }
                }
                return obj;

            case JsonValueKind.Array:
                return element.EnumerateArray().Select(SanitizeJsonElement).ToList();

            case JsonValueKind.String:
                return element.GetString() ?? "";

            case JsonValueKind.Number:
                return element.GetDouble();

            case JsonValueKind.True:
                return true;

            case JsonValueKind.False:
                return false;

            default:
                return null!;
        }
    }

    private string GetStatusCodeName(int statusCode)
    {
        return statusCode switch
        {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => ""
        };
    }

    #endregion
}