using OSK.Security.Cryptography.Models;
using System;
using System.Security.Cryptography;

namespace OSK.Security.Cryptography.Aes.Models
{
    public class AesKeyInformation : SymmetricKeyInformation<AesPublicKeyInformation>
    {
        #region Static

        public static AesKeyInformation New(int keySize, int blockSize = 128,
            PaddingMode paddingMode = PaddingMode.PKCS7, CipherMode cipherMode = CipherMode.CBC)
        {
            using var aes = System.Security.Cryptography.Aes.Create();
            CryptographicKeyHelpers.ValidateKeySize(keySize, aes.LegalKeySizes);

            aes.GenerateKey();
            aes.GenerateIV();
            return new AesKeyInformation(aes.Key, aes.IV, blockSize, paddingMode, cipherMode);
        }

        #endregion

        #region Variables

        public byte[] Key { get; }

        public byte[] IV { get; }

        public int BlockSize { get; }

        public PaddingMode PaddingMode { get; }

        public CipherMode CipherMode { get; }

        #endregion

        #region Constructors

        public AesKeyInformation(byte[] key, byte[] iv, int blockSize,
            PaddingMode paddingMode, CipherMode cipherMode)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            IV = iv ?? throw new ArgumentNullException(nameof(iv));
            BlockSize = blockSize;
            PaddingMode = paddingMode;
            CipherMode = cipherMode;
        }

        public AesKeyInformation(byte[] key, AesPublicKeyInformation publicKeyInformation)
            : this(key, publicKeyInformation.IV, publicKeyInformation.BlockSize,
                  publicKeyInformation.PaddingMode, publicKeyInformation.CipherMode)
        {
        }

        #endregion

        #region CryptographicKey Overrides

        public override AesPublicKeyInformation GetPublicKeyInformation()
        {
            return new AesPublicKeyInformation()
            {
                BlockSize = BlockSize,
                IV = IV,
                CipherMode = CipherMode,
                PaddingMode = PaddingMode
            };
        }

        public override void Dispose()
        {
            Array.Clear(Key, 0, Key.Length);
        }

        #endregion
    }
}
