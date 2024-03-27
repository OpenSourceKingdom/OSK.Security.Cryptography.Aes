using OSK.Security.Cryptography.Aes.Internal.Services;
using OSK.Security.Cryptography.Aes.Models;
using System.Security.Cryptography;

namespace OSK.Security.Cryptography.Aes.UnitTests
{
    public class AesKeyByteKeyTests : CryptographicKeyTests<AesKeyInformation>
    {
        public AesKeyByteKeyTests()
            : base(new AesKeyService(AesKeyInformation.New(RandomNumberGenerator.GetBytes(16))))
        {

        }
    }
}
