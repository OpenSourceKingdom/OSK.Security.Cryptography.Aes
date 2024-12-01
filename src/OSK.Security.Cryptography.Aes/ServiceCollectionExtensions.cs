using Microsoft.Extensions.DependencyInjection;
using OSK.Security.Cryptography.Aes.Internal.Services;
using OSK.Security.Cryptography.Aes.Models;

namespace OSK.Security.Cryptography.Aes
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAesKeyService(this IServiceCollection services)
        {
            services.AddSymmetricKeyService<AesKeyService, AesKeyInformation>("Aes");

            return services;
        }
    }
}
