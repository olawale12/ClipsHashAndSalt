using System;
using System.Security.Cryptography;

namespace ClipsHashAndSalt
{
    public sealed class HashingAndSalting
    {
        private static readonly Lazy<HashingAndSalting> hashingAndSaltingInstance = new Lazy<HashingAndSalting>(() => new HashingAndSalting());

        private static HashingAndSalting GetHashingAndSalting
        {
            get
            {
                return hashingAndSaltingInstance.Value;
            }
        }

        public HashingAndSalting()
        {

        }

        public SaltHashModel GenerateSaltedHash(string password, int size = 64)
        {
            var saltBytes = new byte[size];
            var provider = new RNGCryptoServiceProvider();
            provider.GetNonZeroBytes(saltBytes);
            var salt = Convert.ToBase64String(saltBytes);

            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, saltBytes, 10000);
            var hashPassword = Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(256));

            var hashSalt = new SaltHashModel
            {
                Hash = hashPassword,
                Salt = salt
            };
            return hashSalt;
        }

        public string GenerateSalt(int size = 64)
        {
            var saltBytes = new byte[size];
            var provider = new RNGCryptoServiceProvider();
            provider.GetNonZeroBytes(saltBytes);
            var salt = Convert.ToBase64String(saltBytes);

            return salt;
        }

        public string GenerateHash(string password, string salt)
        {
            var saltBytes = Convert.FromBase64String(salt);
            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, saltBytes, 10000);
            var hashPassword = Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(256));

            return hashPassword;
        }

        public static byte[] GenerateByte(string Salt)
        {
            var saltBytes = Convert.FromBase64String(Salt);
            return saltBytes;
        }

        public static bool VerifyPassword(string Password, string Hash, string Salt)
        {
            var saltBytes = GenerateByte(Salt);
            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(Password, saltBytes, 10000);
            return Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(256)) == Hash;
        }

    }
}
