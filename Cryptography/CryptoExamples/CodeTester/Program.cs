using AsymmetricEncryption;
using DigitalSignatures;
using HashingAlgos;
using HybridEncryption;
using RandomNumberGenerator;
using SymmetricEnryption;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace CodeTester
{
	class Program
	{
		static void Main(string[] args)
		{

			TestHybridEncryption();
			Console.ReadKey();
		}

		private static void TestDigitalSignatures()
		{
			IDigitalSignatureService ser = new RsaDigitalSignatureService(new Sha256HashingService());
			string message = "Hello dear receiver";
			SignMessageResult signMessageResult = ser.SignMessage(message);
			if (signMessageResult.Success)
			{
				Console.WriteLine($"Message signed. Signature base b64: {Environment.NewLine}{Convert.ToBase64String(signMessageResult.Signature)}");
				DigitalSignatureVerificationResult signatureVerificationResult = ser.VerifySignature(signMessageResult);
				if (signatureVerificationResult.Success)
				{
					Console.WriteLine($"Signatures match: {signatureVerificationResult.SignaturesMatch}");
				}
				else
				{
					Console.WriteLine($"Signature verification failure: {signatureVerificationResult.ExceptionMessage}");
				}
			}
			else
			{
				Console.WriteLine($"Message signing failure: {signMessageResult.ExceptionMessage}");
			}
		}

		private static void TestHybridEncryption()
		{
			IXmlBasedAsymmetricEncryptionService asymmetricEncryptionService = new RsaXmlBasedAsymmetricEncryptionService();
			ISymmetricEncryptionService symmetricEncryptionService = new SymmetricEncryptionService(new AesCryptoServiceProvider());
			IHashMacService hashMacService = new HmacSha256Service();
			DigitalSignatures.Alternative.IDigitalSignatureService digitalSignatureService = new DigitalSignatures.Alternative.RsaSigitalSignatureService();
			SecretMessageReceiver secretMessageReceiver = new SecretMessageReceiver(asymmetricEncryptionService, 
				symmetricEncryptionService, hashMacService, digitalSignatureService);
			SecretMessageSender secretMessageSender = 
				new SecretMessageSender(secretMessageReceiver, symmetricEncryptionService, asymmetricEncryptionService, 
				hashMacService, digitalSignatureService);
			secretMessageSender.Start();
		}

		private static void TestAsymmetricEncryptDescryptWithCsp()
		{
			string NL = Environment.NewLine;
			AsymmetricEncryptionService asymmetricEncryptionService = new AsymmetricEncryptionService();
			int keySizeBits = 2048;
			AsymmetricKeyPairPersistenceResult asymmetricKeyPairPersistenceResult =
				asymmetricEncryptionService.PersistNewAsymmetricKeyPair(keySizeBits);
			if (asymmetricKeyPairPersistenceResult.Success)
			{
				Console.WriteLine($"Asymmetric key-pair persistence success.{NL}Container name:{asymmetricKeyPairPersistenceResult.KeyContainerName}{NL}Top key file folder: {asymmetricKeyPairPersistenceResult.KeyStorageTopFolder}{NL}Key-pair file full path: {asymmetricKeyPairPersistenceResult.KeyStorageFileFullPath}{NL}");
				string originalMessage = "This is an extremely secret message.";
				AsymmetricEncryptionResult asymmetricEncryptionResult =
					asymmetricEncryptionService.EncryptWithCspProvider(originalMessage,
						asymmetricKeyPairPersistenceResult.KeyContainerName);
				if (asymmetricEncryptionResult.Success)
				{
					Console.WriteLine("Encryption success.");
					Console.WriteLine($"Cipher text: {NL}{asymmetricEncryptionResult.EncryptedAsBase64}{NL}");
					AsymmetricDecryptionResult asymmetricDecryptionResult =
						asymmetricEncryptionService.DecryptWithCspProvider
						(asymmetricEncryptionResult.EncryptedAsBytes, asymmetricKeyPairPersistenceResult.KeyContainerName);
					if (asymmetricDecryptionResult.Success)
					{
						Console.WriteLine("Decryption success.");
						Console.WriteLine($"Deciphered text: {NL}{asymmetricDecryptionResult.DecryptedMessage}");
					}
					else
					{
						Console.WriteLine($"Decryption failed.{NL}{asymmetricDecryptionResult.ExceptionMessage}");
					}
				}
				else
				{
					Console.WriteLine($"Encryption failed.{NL}{asymmetricEncryptionResult.ExceptionMessage}");
				}
				AsymmetricKeyPairDeletionResult keyPairDeletionResult =
					asymmetricEncryptionService.DeleteAsymmetricKeyPair(asymmetricKeyPairPersistenceResult.KeyContainerName);
				if (keyPairDeletionResult.Success)
				{
					Console.WriteLine("Resources released.");
				}
				else
				{
					Console.WriteLine($"Resource release failed: {keyPairDeletionResult.ExceptionMessage}");
				}
			}
			else
			{
				Console.WriteLine($"Asymmetric key-pair persistence failed.{NL}{asymmetricKeyPairPersistenceResult.ExceptionMessage}");
			}
		}

		private static void TestAsymmetricEncryptDecrypt()
		{
			string NL = Environment.NewLine;
			AsymmetricEncryptionService asymmetricEncryptionService = new AsymmetricEncryptionService();
			int keySizeBits = 2048;
			AsymmetricKeyPairGenerationResult keyPairGenerationResult = asymmetricEncryptionService.GenerateKeysAsXml(keySizeBits);
			if (keyPairGenerationResult.Success)
			{
				XDocument publicKeyXdoc = XDocument.Parse(keyPairGenerationResult.PublicKeyXml);
				XDocument fullKeyXdoc = XDocument.Parse(keyPairGenerationResult.PublicPrivateKeyPairXml);
				Console.WriteLine($"Asymmetric key-pair generation success.{NL}Public key:{NL}{NL}{publicKeyXdoc.ToString()}{NL}{NL}Full key:{NL}{NL}{fullKeyXdoc.ToString()}{NL}{NL}");
				string originalMessage = "This is an extremely secret message.";
				AsymmetricEncryptionResult asymmetricEncryptionResult = asymmetricEncryptionService.EncryptWithPublicKeyXml(originalMessage, keyPairGenerationResult.PublicKeyXml);
				if (asymmetricEncryptionResult.Success)
				{
					Console.WriteLine("Encryption success.");
					Console.WriteLine($"Cipher text: {NL}{asymmetricEncryptionResult.EncryptedAsBase64}{NL}");
					AsymmetricDecryptionResult asymmetricDecryptionResult =
						asymmetricEncryptionService.DecryptWithFullKeyXml
						(asymmetricEncryptionResult.EncryptedAsBytes, keyPairGenerationResult.PublicPrivateKeyPairXml);
					if (asymmetricDecryptionResult.Success)
					{
						Console.WriteLine("Decryption success.");
						Console.WriteLine($"Deciphered text: {NL}{asymmetricDecryptionResult.DecryptedMessage}");
					}
					else
					{
						Console.WriteLine($"Decryption failed.{NL}{asymmetricDecryptionResult.ExceptionMessage}");
					}
				}
				else
				{
					Console.WriteLine($"Encryption failed.{NL}{asymmetricEncryptionResult.ExceptionMessage}");
				}
			}
			else
			{
				Console.WriteLine($"Asymmetric key-pair generation failed.{NL}{keyPairGenerationResult.ExceptionMessage}");
			}
		}

		private static void TestSymmetricEncryptDecrypt()
		{
			string originalMessage = "This is an extremely secret message.";
			List<SymmetricAlgorithm> symmAlgos = new List<SymmetricAlgorithm>()
			{
				new DESCryptoServiceProvider() { KeySize = 64 },
				new TripleDESCryptoServiceProvider() {KeySize = 128 },
				new AesCryptoServiceProvider() { KeySize = 128 },
				new AesManaged() { KeySize = 128 }
			};
			foreach (SymmetricAlgorithm symmAlg in symmAlgos)
			{
				SymmetricEncryptionService symmService = new SymmetricEncryptionService(symmAlg);
				SymmetricEncryptionResult encryptionResult = symmService.Encrypt(originalMessage, 10);
				Console.WriteLine(string.Concat("Encryption result with ", symmAlg.GetType().Name));
				Console.WriteLine("==============================================");
				Console.WriteLine(string.Concat("Success: ", encryptionResult.Success));
				if (encryptionResult.Success)
				{
					Console.WriteLine(string.Concat("Original message: ", originalMessage));
					Console.WriteLine(string.Concat("Symmetric key: ", Convert.ToBase64String(encryptionResult.SymmetricKey)));
					Console.WriteLine(string.Concat("Initialisation vector: ", Convert.ToBase64String(encryptionResult.IV)));
					Console.WriteLine(string.Concat("Ciphertext: ", encryptionResult.CipherBase64));
					Console.WriteLine();
					string decrypted = symmService.Decrypt(encryptionResult.Cipher, encryptionResult.SymmetricKey, encryptionResult.IV);
					Console.WriteLine(string.Concat("Decrypted message: ", decrypted));
				}
				else
				{
					Console.WriteLine(string.Concat("Exception message: ", encryptionResult.ExceptionMessage));
				}
				Console.WriteLine("==============================================");
			}
		}

		private static void TestPkcs()
		{
			string password = "ultra_safe_P455w0rD";
			PKCS pkcs = new PKCS();
			HashWithSaltResult hashResult100Iterations = pkcs.HashPasswordWithPkcs(password, 100, 32);
			HashWithSaltResult hashResult10000Iterations = pkcs.HashPasswordWithPkcs(password, 10000, 32);
			HashWithSaltResult hashResult50000Iterations = pkcs.HashPasswordWithPkcs(password, 50000, 32);

			Stopwatch stopwatch = new Stopwatch();
			stopwatch.Start();
			DateTime start = DateTime.UtcNow;
			Console.WriteLine(hashResult100Iterations.Salt);
			Console.WriteLine(hashResult100Iterations.Digest);
			Console.WriteLine();
			Console.WriteLine(hashResult10000Iterations.Salt);
			Console.WriteLine(hashResult10000Iterations.Digest);
			Console.WriteLine();
			Console.WriteLine(hashResult50000Iterations.Salt);
			Console.WriteLine(hashResult50000Iterations.Digest);

			Thread.Sleep(2000);
			DateTime end = DateTime.UtcNow;
			TimeSpan timeDiff = end - start;
			stopwatch.Stop();
			TimeSpan stopwatchElapsed = stopwatch.Elapsed;
			Console.WriteLine(Convert.ToInt32(stopwatchElapsed.TotalMilliseconds));
			Console.WriteLine(Convert.ToInt32(timeDiff.TotalMilliseconds));
		}

		private static void TestHmac()
		{
			RNG rng = new RNG();
			byte[] hashKey = rng.GenerateRandomCryptographicBytes(64);
			HMACService hmacService = new HMACService();

			string message = "This is another simple message";

			HMAC hmacSha1 = new HMACSHA1(hashKey);
			HMAC hmacSha256 = new HMACSHA256(hashKey);
			HMAC hmacSha512 = new HMACSHA512(hashKey);
			string messageHmacSha1 = hmacService.ComputeHmac(message, hmacSha1);
			string messageHmacSha256 = hmacService.ComputeHmac(message, hmacSha256);
			string messageHmacSha512 = hmacService.ComputeHmac(message, hmacSha512);

			Console.WriteLine(messageHmacSha1);
			Console.WriteLine(messageHmacSha256);
			Console.WriteLine(messageHmacSha512);
		}

		private static void TestRandomNumbers()
		{
			RNG rng = new RNG();
			string random = rng.GenerateRandomCryptographicKey(256);
			byte[] back = Convert.FromBase64String(random);
			Console.WriteLine(random);
		}

		private static void TestPasswordHasher()
		{
			PasswordWithSaltHasher pwHasher = new PasswordWithSaltHasher();
			HashWithSaltResult hashResultSha256 = pwHasher.HashWithSalt("ultra_safe_P455w0rD", 64, SHA256.Create());
			HashWithSaltResult hashResultSha512 = pwHasher.HashWithSalt("ultra_safe_P455w0rD", 64, SHA512.Create());

			Console.WriteLine(hashResultSha256.Salt);
			Console.WriteLine(hashResultSha256.Digest);
			Console.WriteLine();
			Console.WriteLine(hashResultSha512.Salt);
			Console.WriteLine(hashResultSha512.Digest);
		}

		private static void TestHasher()
		{
			Hasher hasher = new Hasher();
			string originalMessage = "H3llo world";
			string messageDigestMd5 = hasher.CalculateMessageDigest(originalMessage, MD5.Create());
			string messageDigestSha1 = hasher.CalculateMessageDigest(originalMessage, SHA1.Create());
			string messageDigestSha256 = hasher.CalculateMessageDigest(originalMessage, SHA256.Create());
			string messageDigestSha512 = hasher.CalculateMessageDigest(originalMessage, SHA512.Create());

			Console.WriteLine(messageDigestMd5);
			Console.WriteLine(messageDigestSha1);
			Console.WriteLine(messageDigestSha256);
			Console.WriteLine(messageDigestSha512);
		}
	}
}
