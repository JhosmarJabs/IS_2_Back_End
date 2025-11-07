using System.ComponentModel.DataAnnotations;

namespace IS_2_Back_End.DTOs.Auth;

public class RegisterRequest
{
    [Required(ErrorMessage = "El email es requerido")]
    [EmailAddress(ErrorMessage = "El formato del email no es válido")]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [MaxLength(50)]
    public string? Phone { get; set; }

    [Required(ErrorMessage = "La contraseña es requerida")]
    [MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres")]
    public string Password { get; set; } = string.Empty;

    [MaxLength(100)]
    public string? Nombre { get; set; }

    [MaxLength(100)]
    public string? Apellido { get; set; }

    [MaxLength(10)]
    public string? Sexo { get; set; } // Ejemplo: "M", "F", "Otro"
}