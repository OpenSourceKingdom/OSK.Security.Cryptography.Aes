using OSK.Security.Cryptography.Aes.Internal.Services;
using OSK.Security.Cryptography.Aes.Models;

namespace OSK.Security.Cryptography.Aes.UnitTests
{
    public class AesKeyKeySizeTests : CryptographicKeyTests<AesKeyInformation>
    {
        public AesKeyKeySizeTests()
            : base(new AesKeyService(AesKeyInformation.New(128)))
        {

        }
    }
}
