# The RSX cipher

### Welcome
The RSX (Rijndael Shake eXtended) cipher, is a hybrid of Rijndael (AES) and the Keccak SHAKE-256 extended output function.

The cipher has four modes, AES128 and AES256, which are the standard AES configurations, and two extended modes, RSX256 and RSX512.

In extended mode, the key schedule has been replaced by SHAKE-256, (or optionally cSHAKE-256), which can safely produce a larger round-key array, enabling an increased number of mixing rounds.
AES-128 has a round count of 10, AES-256 is 14 rounds, RSX-256 is 22 rounds, and RSX-512, which uses a 512 bit cipher input-key, uses 30 rounds.

Increasing the number of rounds, increases the amount of diffusion applied to the state, which makes rijndael harder to break with differential or related subkey based attacks, and by increasing the key size, maintains a high margin of security against future attacks by quantum computers.

### Implementation
The base cipher, Rijndael, and the extended form of the cipher, can operate using one of the three provided cipher modes of operation:
Electronic Code Book mode (ECB), which can be used for testing or creating more complex algorithms,
 a segmented integer counter (CTR), and the Cipher Block Chaining mode (CBC).

This implementation has both a C reference, and an implementation that uses the AES-NI instructions.
The AES-NI implementation can be enabled by adding the RSX_AESNI_ENABLED constant to your preprocessor definitions.

The AES128 and AES256 implementations along with the ECB, CTR, and CBC modes are tested using vectors from SP800-38a.

SP800-38a Block Cipher Modes of Operations: 
http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
See the documentation and the aes_kat.h tests for usage examples.

### License
RSX is licensed as GPLv3
http://www.gnu.org/licenses/

## Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the extended symmetric cipher key length (512 bit), and other cryptographic algorithms contained in this project are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.
