# OSK.Security.Cryptography.Aes
An Aes cryptography service integration with the OSK.Cryptography library. This is backed by microsoft's implementations of the Aes algorithm and is meant
mainly to serve as an easy way to use it. 

# Usage: Consumers
Consumers should inject the core logic using the AddCryptography extension to ensure the necessary services for operation are added to the dependency container. Users can add the Aes cryptographic key service by
using the `AddAesKeyService` service collection extension

# Contributions and Issues
Any and all contributions are appreciated! Please be sure to follow the branch naming convention OSK-{issue number}-{deliminated}-{branch}-{name} as current workflows rely on it for automatic issue closure. Please submit issues for discussion and tracking using the github issue tracker.
