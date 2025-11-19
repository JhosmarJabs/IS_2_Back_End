using System.Text.RegularExpressions;

namespace IS_2_Back_End.Helpers;

public class PasswordValidator
{
    private static readonly string[] CommonPasswords = new[]
    {
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "iloveyou", "trustno1", "1234567890",
        "superman", "qwertyuiop", "1qaz2wsx", "monkey", "password1"
    };

    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new();
        public string? Strength { get; set; }
    }

    public static ValidationResult Validate(string password)
    {
        var result = new ValidationResult { IsValid = true };

        // 1. Longitud mínima
        if (password.Length < 8)
        {
            result.IsValid = false;
            result.Errors.Add("La contraseña debe tener al menos 8 caracteres");
        }

        // 2. Al menos una letra mayúscula
        if (!Regex.IsMatch(password, @"[A-Z]"))
        {
            result.IsValid = false;
            result.Errors.Add("La contraseña debe contener al menos una letra mayúscula");
        }

        // 3. Al menos una letra minúscula
        if (!Regex.IsMatch(password, @"[a-z]"))
        {
            result.IsValid = false;
            result.Errors.Add("La contraseña debe contener al menos una letra minúscula");
        }

        // 4. Al menos un número
        if (!Regex.IsMatch(password, @"[0-9]"))
        {
            result.IsValid = false;
            result.Errors.Add("La contraseña debe contener al menos un número");
        }

        // 5. Al menos un carácter especial
        if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>/?]"))
        {
            result.IsValid = false;
            result.Errors.Add("La contraseña debe contener al menos un carácter especial (!@#$%^&*...)");
        }

        // 6. No puede ser una contraseña común
        if (CommonPasswords.Contains(password.ToLower()))
        {
            result.IsValid = false;
            result.Errors.Add("Esta contraseña es demasiado común. Por favor elige una diferente");
        }

        // 7. No puede tener caracteres repetidos consecutivos (más de 3)
        if (Regex.IsMatch(password, @"(.)\1{3,}"))
        {
            result.IsValid = false;
            result.Errors.Add("La contraseña no puede tener más de 3 caracteres repetidos consecutivos");
        }

        // 8. No puede ser una secuencia simple
        if (IsSequentialPassword(password))
        {
            result.IsValid = false;
            result.Errors.Add("La contraseña no puede ser una secuencia simple (ej: 12345, abcde)");
        }

        // Calcular fortaleza
        if (result.IsValid)
        {
            result.Strength = CalculateStrength(password);
        }

        return result;
    }

    private static bool IsSequentialPassword(string password)
    {
        var sequences = new[]
        {
            "0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"
        };

        password = password.ToLower();
        
        foreach (var sequence in sequences)
        {
            for (int i = 0; i <= sequence.Length - 4; i++)
            {
                var subseq = sequence.Substring(i, 4);
                if (password.Contains(subseq))
                    return true;
            }
        }

        return false;
    }

    private static string CalculateStrength(string password)
    {
        int score = 0;

        // Longitud
        if (password.Length >= 12) score += 2;
        else if (password.Length >= 10) score += 1;

        // Complejidad
        if (Regex.IsMatch(password, @"[A-Z]")) score++;
        if (Regex.IsMatch(password, @"[a-z]")) score++;
        if (Regex.IsMatch(password, @"[0-9]")) score++;
        if (Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>/?]")) score++;

        // Diversidad de caracteres
        var uniqueChars = password.Distinct().Count();
        if (uniqueChars >= password.Length * 0.7) score++;

        // Sin patrones comunes
        if (!Regex.IsMatch(password, @"(\w)\1{2,}")) score++;

        return score switch
        {
            >= 8 => "Muy fuerte",
            >= 6 => "Fuerte",
            >= 4 => "Media",
            _ => "Débil"
        };
    }

    public static string GetPasswordRequirements()
    {
        return "La contraseña debe cumplir con los siguientes requisitos:\n" +
               "• Mínimo 8 caracteres\n" +
               "• Al menos una letra mayúscula (A-Z)\n" +
               "• Al menos una letra minúscula (a-z)\n" +
               "• Al menos un número (0-9)\n" +
               "• Al menos un carácter especial (!@#$%^&*...)\n" +
               "• No puede ser una contraseña común\n" +
               "• No puede tener más de 3 caracteres repetidos consecutivos\n" +
               "• No puede ser una secuencia simple";
    }
}