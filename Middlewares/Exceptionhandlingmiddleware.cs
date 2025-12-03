using System.Net;
using System.Text.Json;
using System.Text;

namespace IS_2_Back_End.Middlewares;

/// <summary>
/// Middleware que captura todas las excepciones y devuelve respuestas consistentes
/// </summary>
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;
    private readonly IHostEnvironment _env;

    public ExceptionHandlingMiddleware(
        RequestDelegate next,
        ILogger<ExceptionHandlingMiddleware> logger,
        IHostEnvironment env)
    {
        _next = next;
        _logger = logger;
        _env = env;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        var correlationId = context.Items["CorrelationId"]?.ToString() ?? "N/A";

        // Log detallado de la excepción
        LogExceptionDetails(exception, correlationId, context);

        // Preparar response
        context.Response.ContentType = "application/json";

        var (statusCode, message) = GetErrorResponse(exception);
        context.Response.StatusCode = (int)statusCode;

        var errorResponse = new ErrorResponse
        {
            CorrelationId = correlationId,
            StatusCode = (int)statusCode,
            Message = message,
            Timestamp = DateTime.UtcNow,
            Path = $"{context.Request.Method} {context.Request.Path}",
            Details = _env.IsDevelopment() ? GetExceptionDetails(exception) : null
        };

        var json = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        });

        await context.Response.WriteAsync(json);
    }

    private void LogExceptionDetails(Exception exception, string correlationId, HttpContext context)
    {
        var logMessage = new StringBuilder();
        logMessage.AppendLine($"\n╔══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ 🔴 UNHANDLED EXCEPTION [{correlationId}]");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ Path:        {context.Request.Method} {context.Request.Path}");
        logMessage.AppendLine($"║ Type:        {exception.GetType().FullName}");
        logMessage.AppendLine($"║ Message:     {exception.Message}");
        logMessage.AppendLine($"║ Source:      {exception.Source}");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine($"║ FULL STACK TRACE:");
        logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
        logMessage.AppendLine(exception.StackTrace ?? "No stack trace available");

        // Inner exceptions
        var innerEx = exception.InnerException;
        var depth = 1;
        while (innerEx != null && depth <= 3)
        {
            logMessage.AppendLine($"╠══════════════════════════════════════════════════════════════════════════════");
            logMessage.AppendLine($"║ INNER EXCEPTION (Level {depth}): {innerEx.GetType().Name}");
            logMessage.AppendLine($"║ Message: {innerEx.Message}");
            logMessage.AppendLine($"║ Stack:");
            logMessage.AppendLine(innerEx.StackTrace ?? "No stack trace");

            innerEx = innerEx.InnerException;
            depth++;
        }

        logMessage.AppendLine($"╚══════════════════════════════════════════════════════════════════════════════");

        _logger.LogError(logMessage.ToString());
    }

    private (HttpStatusCode, string) GetErrorResponse(Exception exception)
    {
        return exception switch
        {
            UnauthorizedAccessException => (HttpStatusCode.Unauthorized, exception.Message),
            InvalidOperationException => (HttpStatusCode.BadRequest, exception.Message),
            ArgumentException => (HttpStatusCode.BadRequest, exception.Message),
            KeyNotFoundException => (HttpStatusCode.NotFound, exception.Message),
            NotImplementedException => (HttpStatusCode.NotImplemented, "Funcionalidad no implementada"),
            TimeoutException => (HttpStatusCode.RequestTimeout, "La operación excedió el tiempo límite"),
            _ => (HttpStatusCode.InternalServerError, "Ocurrió un error interno en el servidor")
        };
    }

    private ExceptionDetails? GetExceptionDetails(Exception exception)
    {
        var details = new ExceptionDetails
        {
            Type = exception.GetType().FullName ?? "Unknown",
            Message = exception.Message,
            StackTrace = exception.StackTrace?.Split('\n').Take(15).ToList() ?? new List<string>(),
            Source = exception.Source,
            InnerExceptions = new List<InnerExceptionInfo>()
        };

        // Capturar inner exceptions
        var innerEx = exception.InnerException;
        var depth = 1;
        while (innerEx != null && depth <= 3)
        {
            details.InnerExceptions.Add(new InnerExceptionInfo
            {
                Level = depth,
                Type = innerEx.GetType().Name,
                Message = innerEx.Message
            });
            innerEx = innerEx.InnerException;
            depth++;
        }

        return details;
    }
}

#region Response Models

public class ErrorResponse
{
    public string CorrelationId { get; set; } = string.Empty;
    public int StatusCode { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string Path { get; set; } = string.Empty;
    public ExceptionDetails? Details { get; set; }
}

public class ExceptionDetails
{
    public string Type { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public List<string> StackTrace { get; set; } = new();
    public string? Source { get; set; }
    public List<InnerExceptionInfo> InnerExceptions { get; set; } = new();
}

public class InnerExceptionInfo
{
    public int Level { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

#endregion