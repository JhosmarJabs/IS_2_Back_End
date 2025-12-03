using Xunit;
using IS_2_Back_End.Helpers;

namespace IS_2_Back_End.Tests.Requirements;

/// <summary>
/// Tests para REQ-002: Validación de entrada (XSS y SQL Injection)
/// </summary>
public class REQ002_InputValidationTests
{
    [Theory]
    [InlineData("admin' OR '1'='1")]
    [InlineData("admin'--")]
    [InlineData("1; DROP TABLE users--")]
    [InlineData("' UNION SELECT * FROM users--")]
    [InlineData("1' OR '1'='1")]
    public void InputSanitizer_ShouldDetectSqlInjection_REQ002(string maliciousInput)
    {
        var containsSqlInjection = InputSanitizer.ContainsSqlInjection(maliciousInput);
        Assert.True(containsSqlInjection, $"No detectó SQL Injection en: {maliciousInput}");
    }

    [Theory]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("<iframe src='http://evil.com'></iframe>")]
    [InlineData("<img src=x onerror=alert('xss')>")]
    [InlineData("javascript:alert('xss')")]
    [InlineData("<embed src='evil.com'>")]
    public void InputSanitizer_ShouldDetectXss_REQ002(string maliciousInput)
    {
        var containsXss = InputSanitizer.ContainsXss(maliciousInput);
        Assert.True(containsXss, $"No detectó XSS en: {maliciousInput}");
    }

    [Fact]
    public void InputSanitizer_ShouldSanitizeValidName_REQ002()
    {
        var validName = "José María";
        var sanitized = InputSanitizer.SanitizeName(validName);
        Assert.Equal("José María", sanitized);
    }

    [Fact]
    public void InputSanitizer_ShouldRejectMaliciousName_REQ002()
    {
        var maliciousName = "José<script>alert('xss')</script>";
        Assert.Throws<ArgumentException>(() => InputSanitizer.SanitizeName(maliciousName));
    }

    [Fact]
    public void InputSanitizer_ShouldSanitizeValidEmail_REQ002()
    {
        var validEmail = "test@example.com";
        var sanitized = InputSanitizer.SanitizeEmail(validEmail);
        Assert.Equal("test@example.com", sanitized);
    }

    [Theory]
    [InlineData("test@example.com' OR '1'='1")]
    [InlineData("admin'--@example.com")]
    public void InputSanitizer_ShouldRejectMaliciousEmail_REQ002(string maliciousEmail)
    {
        Assert.Throws<ArgumentException>(() => InputSanitizer.SanitizeEmail(maliciousEmail));
    }

    [Fact]
    public void InputSanitizer_ShouldSanitizeValidPhone_REQ002()
    {
        var validPhone = "+52 229 123 4567";
        var sanitized = InputSanitizer.SanitizePhone(validPhone);
        Assert.NotNull(sanitized);
        Assert.DoesNotContain(" ", sanitized);
        Assert.DoesNotContain("-", sanitized);
    }

    [Theory]
    [InlineData("123' OR '1'='1")]
    [InlineData("<script>123</script>")]
    public void InputSanitizer_ShouldRejectMaliciousPhone_REQ002(string maliciousPhone)
    {
        Assert.Throws<ArgumentException>(() => InputSanitizer.SanitizePhone(maliciousPhone));
    }
}

/// <summary>
/// Tests para REQ-003: Validación de complejidad de contraseña
/// </summary>
public class REQ003_PasswordComplexityTests
{
    [Theory]
    [InlineData("short")]
    [InlineData("alllowercase1!")]
    [InlineData("ALLUPPERCASE1!")]
    [InlineData("NoNumbers!")]
    [InlineData("NoSpecial123")]
    [InlineData("password")]
    [InlineData("123456")]
    [InlineData("aaaa1111A!")]
    [InlineData("abcdefgh1!")]
    public void PasswordValidator_ShouldRejectWeakPassword_REQ003(string weakPassword)
    {
        var result = PasswordValidator.Validate(weakPassword);
        Assert.False(result.IsValid, $"Aceptó contraseña débil: {weakPassword}");
        Assert.NotEmpty(result.Errors);
    }

    [Theory]
    [InlineData("MyStr0ng!Pass")]
    [InlineData("SecureP@ss123")]
    [InlineData("C0mpl3x!Pass")]
    [InlineData("ValidP@ssw0rd")]
    public void PasswordValidator_ShouldAcceptStrongPassword_REQ003(string strongPassword)
    {
        var result = PasswordValidator.Validate(strongPassword);
        Assert.True(result.IsValid, $"Rechazó contraseña válida: {strongPassword}");
        Assert.Empty(result.Errors);
        Assert.NotNull(result.Strength);
    }

    [Fact]
    public void PasswordValidator_ShouldRejectPasswordsUnder8Characters_REQ003()
    {
        var shortPassword = "Pass1!";
        var result = PasswordValidator.Validate(shortPassword);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("8 caracteres"));
    }

    [Fact]
    public void PasswordValidator_ShouldRequireUppercase_REQ003()
    {
        var noUppercase = "password123!";
        var result = PasswordValidator.Validate(noUppercase);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("mayúscula"));
    }

    [Fact]
    public void PasswordValidator_ShouldRequireLowercase_REQ003()
    {
        var noLowercase = "PASSWORD123!";
        var result = PasswordValidator.Validate(noLowercase);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("minúscula"));
    }

    [Fact]
    public void PasswordValidator_ShouldRequireNumber_REQ003()
    {
        var noNumber = "Password!";
        var result = PasswordValidator.Validate(noNumber);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("número"));
    }

    [Fact]
    public void PasswordValidator_ShouldRequireSpecialCharacter_REQ003()
    {
        var noSpecial = "Password123";
        var result = PasswordValidator.Validate(noSpecial);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("carácter especial"));
    }

    [Fact]
    public void PasswordValidator_ShouldRejectCommonPasswords_REQ003()
    {
        var commonPasswords = new[] { "password", "123456", "qwerty" };
        foreach (var commonPassword in commonPasswords)
        {
            var result = PasswordValidator.Validate(commonPassword);
            Assert.False(result.IsValid, $"Aceptó contraseña común: {commonPassword}");
        }
    }

    [Fact]
    public void PasswordValidator_ShouldCalculateStrength_REQ003()
    {
        var weakPassword = "Pass123!";
        var strongPassword = "MyV3ry!Str0ngP@ssw0rd";
        var weakResult = PasswordValidator.Validate(weakPassword);
        var strongResult = PasswordValidator.Validate(strongPassword);
        Assert.True(weakResult.IsValid);
        Assert.True(strongResult.IsValid);
        Assert.NotNull(weakResult.Strength);
        Assert.NotNull(strongResult.Strength);
    }
}

/// <summary>
/// Tests para REQ-004: Hash seguro de contraseñas
/// </summary>
public class REQ004_PasswordHashingTests
{
    [Fact]
    public void Sha256Hasher_ShouldGenerateUniqueSalts_REQ004()
    {
        var hasher = new Sha256Hasher();
        var salt1 = hasher.GenerateSalt();
        var salt2 = hasher.GenerateSalt();
        var salt3 = hasher.GenerateSalt();
        Assert.NotEqual(salt1, salt2);
        Assert.NotEqual(salt2, salt3);
        Assert.NotEqual(salt1, salt3);
    }

    [Fact]
    public void Sha256Hasher_ShouldHashPassword_REQ004()
    {
        var hasher = new Sha256Hasher();
        var password = "MySecurePassword123!";
        var salt = hasher.GenerateSalt();
        var hash = hasher.HashPassword(password, salt);
        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
        Assert.NotEqual(password, hash);
    }

    [Fact]
    public void Sha256Hasher_SameSaltProducesSameHash_REQ004()
    {
        var hasher = new Sha256Hasher();
        var password = "MySecurePassword123!";
        var salt = hasher.GenerateSalt();
        var hash1 = hasher.HashPassword(password, salt);
        var hash2 = hasher.HashPassword(password, salt);
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void Sha256Hasher_DifferentSaltsProduceDifferentHashes_REQ004()
    {
        var hasher = new Sha256Hasher();
        var password = "MySecurePassword123!";
        var salt1 = hasher.GenerateSalt();
        var salt2 = hasher.GenerateSalt();
        var hash1 = hasher.HashPassword(password, salt1);
        var hash2 = hasher.HashPassword(password, salt2);
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void Sha256Hasher_ShouldVerifyCorrectPassword_REQ004()
    {
        var hasher = new Sha256Hasher();
        var password = "MySecurePassword123!";
        var salt = hasher.GenerateSalt();
        var hash = hasher.HashPassword(password, salt);
        var isValid = hasher.VerifyPassword(password, salt, hash);
        Assert.True(isValid);
    }

    [Fact]
    public void Sha256Hasher_ShouldRejectIncorrectPassword_REQ004()
    {
        var hasher = new Sha256Hasher();
        var correctPassword = "MySecurePassword123!";
        var wrongPassword = "WrongPassword123!";
        var salt = hasher.GenerateSalt();
        var hash = hasher.HashPassword(correctPassword, salt);
        var isValid = hasher.VerifyPassword(wrongPassword, salt, hash);
        Assert.False(isValid);
    }
}

