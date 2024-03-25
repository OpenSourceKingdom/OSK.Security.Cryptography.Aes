using OSK.Security.Cryptography.Aes.Internal.Services;
using OSK.Security.Cryptography.Aes.Models;

namespace OSK.Security.Cryptography.Aes.UnitTests
{
    public class AesKeyTests : CryptographicKeyTests<AesKeyInformation>
    {
        public AesKeyTests()
            : base(new AesKeyService(AesKeyInformation.New(128)))
        {

        }
    }
}
