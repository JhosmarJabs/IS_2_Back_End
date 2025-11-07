using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IS_2_Back_End.Entities
{
    [Table("users")]
    public class User
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("email")]
        [MaxLength(255)]
        public string Email { get; set; } = string.Empty;

        [Column("phone")]
        [MaxLength(50)]
        public string? Phone { get; set; }

        [Required]
        [Column("password_hash")]
        [MaxLength(255)]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        [Column("salt")]
        [MaxLength(50)]
        public string Salt { get; set; } = string.Empty;

        [Column("is_verified")]
        public bool IsVerified { get; set; } = false;

        [Column("nombre")]
        [MaxLength(100)]
        public string? Nombre { get; set; }

        [Column("apellido")]
        [MaxLength(100)]
        public string? Apellido { get; set; }

        [Column("sexo")]
        [MaxLength(10)]
        public string? Sexo { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Column("updated_at")]
        public DateTime? UpdatedAt { get; set; }

        // Relaciones
        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
        public ICollection<VerificationToken> VerificationTokens { get; set; } = new List<VerificationToken>();
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }

    [Table("roles")]
    public class Role
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("name")]
        public string Name { get; set; } = string.Empty;

        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    }

    [Table("user_roles")]
    public class UserRole
    {
        [Column("user_id")]
        public int UserId { get; set; }
        public User User { get; set; } = null!;

        [Column("role_id")]
        public int RoleId { get; set; }
        public Role Role { get; set; } = null!;

        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    [Table("verification_tokens")]
    public class VerificationToken
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Column("user_id")]
        public int UserId { get; set; }
        public User User { get; set; } = null!;

        [Required]
        [Column("token")]
        public string Token { get; set; } = string.Empty;

        [Required]
        [Column("purpose")]
        public string Purpose { get; set; } = string.Empty;

        [Column("payload")]
        public string? Payload { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Column("expires_at")]
        public DateTime ExpiresAt { get; set; }

        [Column("consumed")]
        public bool Consumed { get; set; } = false;

        [Column("consumed_at")]
        public DateTime? ConsumedAt { get; set; }
    }

    [Table("refresh_tokens")]
    public class RefreshToken
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Column("user_id")]
        public int UserId { get; set; }
        public User User { get; set; } = null!;

        [Required]
        [Column("token_hash")]
        public string TokenHash { get; set; } = string.Empty;

        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Column("expires_at")]
        public DateTime ExpiresAt { get; set; }

        [Column("revoked")]
        public bool Revoked { get; set; } = false;

        [Column("revoked_at")]
        public DateTime? RevokedAt { get; set; }
    }
}