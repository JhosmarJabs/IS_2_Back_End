namespace IS_2_Back_End.Attributes;

/// <summary>
/// Atributo para documentar requerimientos implementados en métodos
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public class RequirementAttribute : Attribute
{
    /// <summary>
    /// Código del requerimiento (ej: REQ-001)
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Descripción del requerimiento
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Archivo(s) donde está implementado
    /// </summary>
    public string? Files { get; set; }

    public RequirementAttribute(string code, string description)
    {
        Code = code;
        Description = description;
    }
}