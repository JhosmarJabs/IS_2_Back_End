using System.Text.RegularExpressions;
using System.Web;

namespace IS_2_Back_End.Helpers;

/// <summary>
/// Sanitiza y valida entradas de usuario para prevenir XSS y SQL Injection
/// </summary>
public static class InputSanitizer
{
    // Patrones peligrosos de SQL Injection
    private static readonly string[] SqlInjectionPatterns = new[]
    {
        @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        @"(--|;|\/\*|\*\/|xp_|sp_)",
        @"('|\bOR\b|\bAND\b).*?=",
        @"(\bUNION\b.*?\bSELECT\b)",
        @"(\b1\s*=\s*1\b)"
    };

    // Patrones peligrosos de XSS
    private static readonly string[] XssPatterns = new[]
    {
        @"<script[^>]*>.*?</script>",
        @"<iframe[^>]*>.*?</iframe>",
        @"javascript:",
        @"on\w+\s*=",
        @"<embed[^>]*>",
        @"<object[^>]*>",
        @"<applet[^>]*>"
    };

    /// <summary>
    /// Sanitiza un string previniendo XSS
    /// </summary>
    public static string SanitizeForXss(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        // Encode HTML
        var sanitized = HttpUtility.HtmlEncode(input);

        // Remover patrones peligrosos
        foreach (var pattern in XssPatterns)
        {
            sanitized = Regex.Replace(sanitized, pattern, "", RegexOptions.IgnoreCase);
        }

        return sanitized;
    }

    /// <summary>
    /// Valida que no contenga patrones de SQL Injection
    /// </summary>
    public static bool ContainsSqlInjection(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        foreach (var pattern in SqlInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Valida que no contenga patrones de XSS
    /// </summary>
    public static bool ContainsXss(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        foreach (var pattern in XssPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Sanitiza un email
    /// </summary>
    public static string SanitizeEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
            return email;

        // Remover espacios
        email = email.Trim();

        // Validar formato básico
        if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            throw new ArgumentException("Formato de email inválido");

        // Prevenir inyección
        if (ContainsSqlInjection(email) || ContainsXss(email))
            throw new ArgumentException("Email contiene caracteres no permitidos");

        return email.ToLower();
    }

    /// <summary>
    /// Sanitiza un nombre (nombre, apellido)
    /// </summary>
    public static string? SanitizeName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return name;

        // Remover espacios extra
        name = name.Trim();
        name = Regex.Replace(name, @"\s+", " ");

        // Solo permitir letras, espacios, guiones y apóstrofes
        if (!Regex.IsMatch(name, @"^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s\-']+$"))
            throw new ArgumentException("El nombre contiene caracteres no permitidos");

        // Prevenir XSS y SQL Injection
        if (ContainsSqlInjection(name) || ContainsXss(name))
            throw new ArgumentException("El nombre contiene caracteres no permitidos");

        return name;
    }

    /// <summary>
    /// Sanitiza un teléfono
    /// </summary>
    public static string? SanitizePhone(string? phone)
    {
        if (string.IsNullOrWhiteSpace(phone))
            return phone;

        // Remover espacios y caracteres especiales permitidos
        phone = phone.Trim();
        phone = Regex.Replace(phone, @"[\s\-\(\)]", "");

        // Solo permitir números y símbolo +
        if (!Regex.IsMatch(phone, @"^\+?[0-9]+$"))
            throw new ArgumentException("El teléfono contiene caracteres no permitidos");

        if (phone.Length < 10 || phone.Length > 15)
            throw new ArgumentException("Longitud de teléfono inválida");

        return phone;
    }

    /// <summary>
    /// Valida y sanitiza todos los campos de registro
    /// </summary>
    public static class Validation
    {
        public static (bool isValid, List<string> errors) ValidateRegistration(
            string email, string? phone, string? nombre, string? apellido, string? sexo)
        {
            var errors = new List<string>();

            try
            {
                if (!string.IsNullOrEmpty(email))
                    SanitizeEmail(email);
            }
            catch (Exception ex)
            {
                errors.Add($"Email: {ex.Message}");
            }

            try
            {
                if (!string.IsNullOrEmpty(phone))
                    SanitizePhone(phone);
            }
            catch (Exception ex)
            {
                errors.Add($"Teléfono: {ex.Message}");
            }

            try
            {
                if (!string.IsNullOrEmpty(nombre))
                    SanitizeName(nombre);
            }
            catch (Exception ex)
            {
                errors.Add($"Nombre: {ex.Message}");
            }

            try
            {
                if (!string.IsNullOrEmpty(apellido))
                    SanitizeName(apellido);
            }
            catch (Exception ex)
            {
                errors.Add($"Apellido: {ex.Message}");
            }

            if (!string.IsNullOrEmpty(sexo) && !new[] { "M", "F", "Otro" }.Contains(sexo))
            {
                errors.Add("Sexo: Valor no válido");
            }

            return (errors.Count == 0, errors);
        }
    }
}