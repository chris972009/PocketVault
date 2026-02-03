using System;
using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace PocketVault.Core.Models
{
    internal class StreamEncryptor
    {
        private const int _saltSize = 32;
        private const int _keySize = 32;
        private static readonly int _masterKeySize = _keySize * 2;
        private const int _hmacSize = 32;
        private const int _ivSize = 16;
        private const int _iterations = 100_00;
        private static readonly HashAlgorithmName _algorithmName = HashAlgorithmName.SHA256;
        private const int _bufferSize = 91_820;

        public async Task EncryptAsync(Stream inputStream, Stream outputStream, string password, IProgress<double>? progress, CancellationToken cancellationToken)
        {
            var salt = RandomNumberGenerator.GetBytes(_saltSize);
            var masterKey = Rfc2898DeriveBytes.Pbkdf2(password, salt, _iterations, _algorithmName, _masterKeySize);
            using var aes = Aes.Create();
            aes.Key = masterKey.Take(_keySize).ToArray();
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor();

            var hmacKey = masterKey.Skip(_keySize).Take(_keySize).ToArray();
            using var hmac = new HMACSHA256(hmacKey);
            hmac.TransformBlock(salt, 0, _saltSize, null, 0);
            hmac.TransformBlock(aes.IV, 0, _ivSize, null, 0);

            var bytesToRead = inputStream.Length;
            double totalBytesRead = 0;
            int bytesRead = 0;
            var buffer = new byte[_bufferSize];
            await outputStream.WriteAsync(salt, cancellationToken);
            await outputStream.WriteAsync(aes.IV, cancellationToken);
            while((bytesRead = await inputStream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                totalBytesRead += (long)bytesRead;
                byte[] cryptoBytes;
                if (totalBytesRead < bytesToRead)
                {
                    cryptoBytes = new byte[bytesRead];
                    encryptor.TransformBlock(buffer, 0, bytesRead, cryptoBytes, 0);
                }
                else
                {
                    cryptoBytes = encryptor.TransformFinalBlock(buffer, 0, bytesRead);
                }
                await outputStream.WriteAsync(cryptoBytes, 0, bytesRead, cancellationToken);
                hmac.TransformBlock(cryptoBytes, 0, cryptoBytes.Length, null, 0);

                progress?.Report(totalBytesRead / bytesToRead);
            }

            var hash = hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            await outputStream.WriteAsync(hash, cancellationToken);
        }

        public async Task DecryptAsync(Stream inputStream, Stream outputStream, string password, IProgress<double>? progress, CancellationToken cancellationToken)
        {
            var bytesToRead = inputStream.Length - _saltSize - _ivSize - _hmacSize;
            if (bytesToRead < 1) throw new InvalidDataException("Input is too small for a valid encrypted stream");
            var salt = new byte[_saltSize];
            await inputStream.ReadExactlyAsync(salt);
            var iv = new byte[_ivSize];
            await inputStream.ReadExactlyAsync(iv);

            var masterKey = Rfc2898DeriveBytes.Pbkdf2(password, salt, _iterations, _algorithmName, _masterKeySize);
            var aesKey = masterKey.Take(_keySize).ToArray();
            var hmacKey = masterKey.Skip(_keySize).Take(_keySize).ToArray();
            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.IV = iv;
            using var decryptor = aes.CreateDecryptor();
            using var hmac = new HMACSHA256(hmacKey);
            hmac.TransformBlock(salt, 0, _saltSize, null, 0);
            hmac.TransformBlock(iv, 0, _ivSize, null, 0);

            double totalBytesRead = 0;
            var buffer = new byte[_bufferSize];
            while (totalBytesRead < bytesToRead)
            {
                var bytesRead = await inputStream.ReadAsync(buffer, cancellationToken);
                totalBytesRead += (long)bytesRead;

                hmac.TransformBlock(buffer, 0, bytesRead, null, 0);
                byte[] plainBytes;
                if (totalBytesRead < bytesToRead)
                {
                    plainBytes = new byte[bytesRead];
                    decryptor.TransformBlock(buffer, 0, bytesRead, plainBytes, 0);
                }
                else
                {
                    plainBytes = decryptor.TransformFinalBlock(buffer, 0, bytesRead);
                }
                await outputStream.WriteAsync(plainBytes, 0, plainBytes.Length, cancellationToken);

                progress?.Report(totalBytesRead / bytesToRead);
            }

            var computedHash = hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            var storedHash = new byte[_hmacSize];
            await inputStream.ReadExactlyAsync(storedHash, cancellationToken);

            if (!computedHash.SequenceEqual(storedHash))
                throw new CryptographicException("Data integrity check failed. The password may be incorrect or the data has been tampered with.");

        }
    }
}