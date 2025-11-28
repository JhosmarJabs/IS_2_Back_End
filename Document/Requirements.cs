namespace IS_2_Back_End.Document;

/// <summary>
/// Constantes para códigos de requerimientos de seguridad del sistema
/// Basado en los 30+ criterios de seguridad del proyecto
/// </summary>
public static class Requirements
{
    /// <summary>
    /// REQ-001: Verificación de correo electrónico obligatoria
    /// El sistema debe bloquear el inicio de sesión si el email no ha sido verificado
    /// </summary>
    public const string EMAIL_VERIFICATION_REQUIRED = "REQ-001";

    /// <summary>
    /// REQ-002: Validación de datos de entrada (XSS y SQL Injection)
    /// Todos los inputs deben ser sanitizados y validados
    /// </summary>
    public const string INPUT_VALIDATION_REQUIRED = "REQ-002";

    /// <summary>
    /// REQ-003: Requisitos de complejidad de contraseña
    /// Las contraseñas deben cumplir requisitos de seguridad robustos
    /// </summary>
    public const string PASSWORD_COMPLEXITY_REQUIRED = "REQ-003";

    /// <summary>
    /// REQ-004: Hash seguro de contraseñas con SHA256 + Salt único
    /// No debe haber contraseñas en texto plano en la base de datos
    /// </summary>
    public const string PASSWORD_HASHING_REQUIRED = "REQ-004";

    /// <summary>
    /// REQ-005: Recuperación de contraseña con enlace que expira
    /// Los enlaces de recuperación deben expirar en tiempo definido
    /// </summary>
    public const string PASSWORD_RECOVERY_EXPIRATION = "REQ-005";

    /// <summary>
    /// REQ-006: Validación de usuario en recuperación
    /// No debe revelar si el email existe en el sistema
    /// </summary>
    public const string USER_ENUMERATION_PROTECTION = "REQ-006";

    /// <summary>
    /// REQ-007: Limitación de intentos de recuperación
    /// Limitar intentos de recuperación de contraseña por IP
    /// </summary>
    public const string RECOVERY_RATE_LIMITING = "REQ-007";

    /// <summary>
    /// REQ-008: Bloqueo tras intentos fallidos de login
    /// Bloquear cuenta temporalmente después de N intentos fallidos
    /// </summary>
    public const string LOGIN_ATTEMPT_LIMITING = "REQ-008";

    /// <summary>
    /// REQ-009: Uso de HTTPS obligatorio
    /// Todas las comunicaciones deben usar HTTPS con certificados válidos
    /// </summary>
    public const string HTTPS_REQUIRED = "REQ-009";

    /// <summary>
    /// REQ-010: Sesiones con expiración automática
    /// Las sesiones inactivas deben expirar automáticamente
    /// </summary>
    public const string SESSION_EXPIRATION = "REQ-010";

    /// <summary>
    /// REQ-011: Tokens JWT seguros con algoritmo HS256/RS256
    /// Tokens deben tener estructura segura y expiración definida
    /// </summary>
    public const string JWT_SECURITY = "REQ-011";

    /// <summary>
    /// REQ-012: Uso de salts únicos en hashing de contraseñas
    /// Cada contraseña debe tener un salt único y aleatorio
    /// </summary>
    public const string UNIQUE_SALT_REQUIRED = "REQ-012";

    /// <summary>
    /// REQ-013: Política de longitud mínima de contraseña
    /// Contraseñas deben tener mínimo 8 caracteres
    /// </summary>
    public const string PASSWORD_MIN_LENGTH = "REQ-013";

    /// <summary>
    /// REQ-014: Revocación de sesiones activas
    /// Cerrar sesión en un dispositivo debe invalidar tokens en todos
    /// </summary>
    public const string SESSION_REVOCATION = "REQ-014";

    /// <summary>
    /// REQ-015: Contraseñas cifradas en tránsito
    /// Contraseñas no deben viajar en texto plano (HTTPS/TLS)
    /// </summary>
    public const string TRANSIT_ENCRYPTION = "REQ-015";

    /// <summary>
    /// REQ-016: Protección contra XSS
    /// Scripts maliciosos no deben ejecutarse
    /// </summary>
    public const string XSS_PROTECTION = "REQ-016";

    /// <summary>
    /// REQ-017: Protección contra CSRF
    /// Tokens CSRF en peticiones state-changing
    /// </summary>
    public const string CSRF_PROTECTION = "REQ-017";

    /// <summary>
    /// REQ-018: Protección contra inyecciones SQL
    /// Queries parametrizadas y validación de entrada
    /// </summary>
    public const string SQL_INJECTION_PROTECTION = "REQ-018";

    /// <summary>
    /// REQ-019: Cabeceras de seguridad HTTP
    /// CSP, HSTS, X-Frame-Options, etc.
    /// </summary>
    public const string SECURITY_HEADERS_REQUIRED = "REQ-019";

    /// <summary>
    /// REQ-020: Autenticación multifactor (MFA)
    /// Segundo factor obligatorio para acceso
    /// </summary>
    public const string MFA_REQUIRED = "REQ-020";

    /// <summary>
    /// REQ-021: OAuth2.0 seguro
    /// Flujo Authorization Code sin exponer tokens
    /// </summary>
    public const string OAUTH2_SECURITY = "REQ-021";

    /// <summary>
    /// REQ-022: Revisión de dependencias seguras
    /// Sin vulnerabilidades conocidas (CVEs) en dependencias
    /// </summary>
    public const string DEPENDENCY_SECURITY = "REQ-022";

    /// <summary>
    /// REQ-023: Logging seguro
    /// Logs no deben contener datos sensibles
    /// </summary>
    public const string SECURE_LOGGING = "REQ-023";

    /// <summary>
    /// REQ-024: Control de acceso basado en roles (RBAC)
    /// Usuarios no deben acceder a recursos no autorizados
    /// </summary>
    public const string RBAC_REQUIRED = "REQ-024";

    /// <summary>
    /// REQ-025: Pruebas de inyección SQL/NoSQL
    /// Testing con herramientas automatizadas
    /// </summary>
    public const string INJECTION_TESTING = "REQ-025";

    /// <summary>
    /// REQ-026: Pruebas de XSS automatizadas
    /// Escaneo con OWASP ZAP u otras herramientas
    /// </summary>
    public const string XSS_TESTING = "REQ-026";

    /// <summary>
    /// REQ-027: Validación de invalidación de tokens
    /// Tokens deben invalidarse inmediatamente al logout
    /// </summary>
    public const string TOKEN_INVALIDATION = "REQ-027";

    /// <summary>
    /// REQ-028: Análisis de vulnerabilidades en dependencias
    /// Escaneo regular con npm audit, Snyk, etc.
    /// </summary>
    public const string VULNERABILITY_SCANNING = "REQ-028";

    /// <summary>
    /// REQ-029: Configuración HTTP/TLS segura
    /// Solo TLS 1.2+, calificación A- mínimo en SSL Labs
    /// </summary>
    public const string TLS_CONFIGURATION = "REQ-029";

    /// <summary>
    /// REQ-030: Cookies seguras
    /// HttpOnly, Secure y SameSite en todas las cookies
    /// </summary>
    public const string SECURE_COOKIES = "REQ-030";


    /// <summary>
    /// Grupo: Requerimientos de Autenticación
    /// </summary>
    public static class Authentication
    {
        public const string EmailVerification = EMAIL_VERIFICATION_REQUIRED;
        public const string PasswordComplexity = PASSWORD_COMPLEXITY_REQUIRED;
        public const string PasswordHashing = PASSWORD_HASHING_REQUIRED;
        public const string LoginAttemptLimiting = LOGIN_ATTEMPT_LIMITING;
        public const string SessionExpiration = SESSION_EXPIRATION;
        public const string SessionRevocation = SESSION_REVOCATION;
        public const string MFA = MFA_REQUIRED;
        public const string OAuth2 = OAUTH2_SECURITY;
    }

    /// <summary>
    /// Grupo: Requerimientos de Protección de Datos
    /// </summary>
    public static class DataProtection
    {
        public const string InputValidation = INPUT_VALIDATION_REQUIRED;
        public const string XSSProtection = XSS_PROTECTION;
        public const string SQLInjectionProtection = SQL_INJECTION_PROTECTION;
        public const string CSRFProtection = CSRF_PROTECTION;
        public const string SecureLogging = SECURE_LOGGING;
    }

    /// <summary>
    /// Grupo: Requerimientos de Criptografía
    /// </summary>
    public static class Cryptography
    {
        public const string PasswordHashing = PASSWORD_HASHING_REQUIRED;
        public const string UniqueSalt = UNIQUE_SALT_REQUIRED;
        public const string TransitEncryption = TRANSIT_ENCRYPTION;
        public const string TLSConfiguration = TLS_CONFIGURATION;
        public const string JWTSecurity = JWT_SECURITY;
    }

    /// <summary>
    /// Grupo: Requerimientos de Seguridad de Red
    /// </summary>
    public static class NetworkSecurity
    {
        public const string HTTPS = HTTPS_REQUIRED;
        public const string SecurityHeaders = SECURITY_HEADERS_REQUIRED;
        public const string TLS = TLS_CONFIGURATION;
        public const string SecureCookies = SECURE_COOKIES;
    }

    /// <summary>
    /// Grupo: Requerimientos de Testing y Auditoría
    /// </summary>
    public static class Testing
    {
        public const string DependencySecurity = DEPENDENCY_SECURITY;
        public const string InjectionTesting = INJECTION_TESTING;
        public const string XSSTesting = XSS_TESTING;
        public const string VulnerabilityScanning = VULNERABILITY_SCANNING;
    }

    /// <summary>
    /// Grupo: Requerimientos de Control de Acceso
    /// </summary>
    public static class AccessControl
    {
        public const string RBAC = RBAC_REQUIRED;
        public const string UserEnumerationProtection = USER_ENUMERATION_PROTECTION;
        public const string RecoveryRateLimiting = RECOVERY_RATE_LIMITING;
        public const string LoginAttemptLimiting = LOGIN_ATTEMPT_LIMITING;
    }


    /// <summary>
    /// Obtiene todos los requerimientos implementados
    /// </summary>
    public static string[] GetImplemented()
    {
        return new[]
        {
            EMAIL_VERIFICATION_REQUIRED,
            INPUT_VALIDATION_REQUIRED,
            PASSWORD_COMPLEXITY_REQUIRED,
            PASSWORD_HASHING_REQUIRED,
            PASSWORD_RECOVERY_EXPIRATION,
            USER_ENUMERATION_PROTECTION,
            RECOVERY_RATE_LIMITING,
            LOGIN_ATTEMPT_LIMITING,
            HTTPS_REQUIRED,
            SESSION_EXPIRATION,
            JWT_SECURITY,
            UNIQUE_SALT_REQUIRED,
            PASSWORD_MIN_LENGTH
        };
    }

    /// <summary>
    /// Obtiene todos los requerimientos parcialmente implementados
    /// </summary>
    public static string[] GetPartiallyImplemented()
    {
        return new[]
        {
            SESSION_REVOCATION,
            TRANSIT_ENCRYPTION,
            XSS_PROTECTION,
            CSRF_PROTECTION,
            SQL_INJECTION_PROTECTION,
            SECURITY_HEADERS_REQUIRED
        };
    }

    /// <summary>
    /// Obtiene todos los requerimientos no implementados
    /// </summary>
    public static string[] GetNotImplemented()
    {
        return new[]
        {
            MFA_REQUIRED,
            OAUTH2_SECURITY,
            DEPENDENCY_SECURITY,
            SECURE_LOGGING,
            RBAC_REQUIRED,
            INJECTION_TESTING,
            XSS_TESTING,
            TOKEN_INVALIDATION,
            VULNERABILITY_SCANNING,
            TLS_CONFIGURATION,
            SECURE_COOKIES
        };
    }

    /// <summary>
    /// Obtiene el porcentaje de implementación
    /// </summary>
    public static (int total, int implemented, int partial, int notImplemented, double percentage) GetCoverageStats()
    {
        var implemented = GetImplemented().Length;
        var partial = GetPartiallyImplemented().Length;
        var notImplemented = GetNotImplemented().Length;
        var total = implemented + partial + notImplemented;
        var percentage = ((double)implemented / total) * 100;

        return (total, implemented, partial, notImplemented, percentage);
    }
}