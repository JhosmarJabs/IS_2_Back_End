namespace IS_2_Back_End.DTOs.Auth
{
    public class VerifyTokenRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
    }
}
