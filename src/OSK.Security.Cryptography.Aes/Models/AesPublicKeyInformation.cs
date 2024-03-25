using OSK.Security.Cryptography.Abstractions;
using System.Security.Cryptography;

namespace OSK.Security.Cryptography.Aes.Models
{
    public class AesPublicKeyInformation : PublicKeyInformation
    {
        public byte[] IV { get; set; }

        public int BlockSize { get; set; }

        public PaddingMode PaddingMode { get; set; }

        public CipherMode CipherMode { get; set; }
    }
}
