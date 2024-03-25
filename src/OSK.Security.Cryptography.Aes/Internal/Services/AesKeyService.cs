using System.IO;
using System.Security.Cryptography;
using System;
using System.Threading;
using System.Threading.Tasks;
using OSK.Security.Cryptography;
using OSK.Security.Cryptography.Aes.Models;

namespace OSK.Security.Cryptography.Aes.Internal.Services
{
    internal class AesKeyService : SymmetricKeyService<AesKeyInformation>
    {
        #region Constructors

        public AesKeyService(AesKeyInformation keyInformation)
            : base(keyInformation)
        {
        }

        #endregion

        #region CryptographicKeyService Overrides

        public override async ValueTask<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var aes = new AesManaged();
            aes.BlockSize = KeyInformation.BlockSize;
            aes.Padding = KeyInformation.PaddingMode;
            aes.Key = KeyInformation.Key;
            aes.IV = KeyInformation.IV;
            aes.Mode = KeyInformation.CipherMode;

            using var dataStream = new MemoryStream(data);
            var encryptedDataStream = new MemoryStream();
            var cryptoStream = new CryptoStream(encryptedDataStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            await dataStream.CopyToAsync(cryptoStream, cancellationToken);
            cryptoStream.FlushFinalBlock();
            return encryptedDataStream.ToArray();
        }

        public override async ValueTask<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var aes = new AesManaged();
            aes.BlockSize = KeyInformation.BlockSize;
            aes.Padding = KeyInformation.PaddingMode;
            aes.Key = KeyInformation.Key;
            aes.IV = KeyInformation.IV;
            aes.Mode = KeyInformation.CipherMode;

            using var encryptedDataStream = new MemoryStream(data);
            using var cryptoStream = new CryptoStream(encryptedDataStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var decryptedStream = new MemoryStream();
            await cryptoStream.CopyToAsync(decryptedStream, cancellationToken);
            return decryptedStream.ToArray();
        }

        #endregion
    }
}
