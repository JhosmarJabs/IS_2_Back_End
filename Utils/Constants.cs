namespace IS_2_Back_End.Utils;

public static class Constants
{
    // Role IDs - según tu base de datos
    public const int UserRoleId = 1;     // 'user'
    public const int ManagerRoleId = 2;  // 'manager'

    // Role Names
    public const string UserRole = "user";
    public const string ManagerRole = "manager";

    // Token Expiration
    public const int VerificationTokenExpirationMinutes = 15;
    public const int RefreshTokenExpirationDays = 30;
    public const int AccessTokenExpirationMinutes = 60;

    // Validation
    public const int MinPasswordLength = 8;
    public const int MaxPasswordLength = 100;
    public const int OtpCodeLength = 6;
    
    // Token Purposes
    public const string EmailVerification = "email_verification";
    public const string MagicLink = "magic_link";
    public const string OtpPurpose = "otp";
}