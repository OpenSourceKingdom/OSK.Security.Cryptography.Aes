using OSK.Security.Cryptography.Models;
using System;
using System.Security.Cryptography;

namespace OSK.Security.Cryptography.Aes.Models
{
    public class AesKeyInformation : SymmetricKeyInformation<AesPublicKeyInformation>
    {
        #region Static

        /// <summary>
        /// Returns an array of the valid key sizes for the Aes encryption implementation
        /// </summary>
        /// <returns>The array of <see cref="KeySizes"/> that are valid for use with this implementation</returns>
        public static KeySizes[] GetValidKeySizes()
        {
            using var aes = System.Security.Cryptography.Aes.Create();
            return aes.LegalKeySizes;
        }

        public static AesKeyInformation New(int keySize, int blockSize = 128,
            PaddingMode paddingMode = PaddingMode.PKCS7, CipherMode cipherMode = CipherMode.CBC)
        {
            using var aes = System.Security.Cryptography.Aes.Create();
            CryptographicKeyHelpers.ValidateKeySize(keySize, aes.LegalKeySizes);

            aes.KeySize = keySize;
            aes.GenerateKey();
            aes.GenerateIV();
            return new AesKeyInformation(aes.Key, aes.IV, blockSize, paddingMode, cipherMode);
        }

        public static AesKeyInformation New(byte[] key, int blockSize = 128,
            PaddingMode paddingMode = PaddingMode.PKCS7, CipherMode cipherMode = CipherMode.CBC)
        {
            using var aes = System.Security.Cryptography.Aes.Create();

            aes.Key = key;
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
