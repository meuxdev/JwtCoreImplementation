using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtCoreImplementation
{
    public class User
    {
        public string Username { get; set; } = string.Empty;

        public byte[] PasswordHash { get; set; } = new byte[8];

        public byte[] PasswordSalt { get; set; } = new byte[8];
    }
}