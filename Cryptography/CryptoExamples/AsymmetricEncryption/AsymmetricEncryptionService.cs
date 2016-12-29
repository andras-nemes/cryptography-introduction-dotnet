using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Xml.Linq;
using System.IO;

namespace AsymmetricEncryption
{
	public class AsymmetricEncryptionService : IXmlBasedAsymmetricEncryptionService
	{
		public AsymmetricKeyPairGenerationResult GenerateKeysAsXml(int keySizeBits)
		{
			AsymmetricKeyPairGenerationResult asymmetricKeyPairGenerationResult = new AsymmetricKeyPairGenerationResult();
			RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(keySizeBits);
			try
			{
				asymmetricKeyPairGenerationResult.PublicKeyXml = rsaProvider.ToXmlString(false);
				asymmetricKeyPairGenerationResult.PublicPrivateKeyPairXml = rsaProvider.ToXmlString(true);
				asymmetricKeyPairGenerationResult.Success = true;
			}
			catch (CryptographicException cex)
			{
				string NL = Environment.NewLine;
				StringBuilder validKeySizeBuilder = new StringBuilder();
				KeySizes[] validKeySizes = rsaProvider.LegalKeySizes;
				foreach (KeySizes keySizes in validKeySizes)
				{
					validKeySizeBuilder.Append("Min: ")
						.Append(keySizes.MinSize).Append(NL)
						.Append("Max: ").Append(keySizes.MaxSize).Append(NL)
						.Append("Step: ").Append(keySizes.SkipSize);
				}
				asymmetricKeyPairGenerationResult.ExceptionMessage =
					$"Cryptographic exception when generating a key-pair of size {keySizeBits}. Exception: {cex.Message}{NL}Make sure you provide a valid key size. Here are the valid key size boundaries:{NL}{validKeySizeBuilder.ToString()}";
			}
			catch (Exception otherEx)
			{
				asymmetricKeyPairGenerationResult.ExceptionMessage =
					$"Other exception caught while generating the key pair: {otherEx.Message}";
			}
			return asymmetricKeyPairGenerationResult;
		}

		public AsymmetricEncryptionResult EncryptWithPublicKeyXml(string message, string publicKeyAsXml)
		{
			AsymmetricEncryptionResult asymmetricEncryptionResult = new AsymmetricEncryptionResult();
			try
			{
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
				rsaProvider.FromXmlString(publicKeyAsXml);
				byte[] encryptedAsBytes = rsaProvider.Encrypt(Encoding.UTF8.GetBytes(message), true);
				string encryptedAsBase64 = Convert.ToBase64String(encryptedAsBytes);
				asymmetricEncryptionResult.EncryptedAsBase64 = encryptedAsBase64;
				asymmetricEncryptionResult.EncryptedAsBytes = encryptedAsBytes;
				asymmetricEncryptionResult.Success = true;
			}
			catch (Exception ex)
			{
				asymmetricEncryptionResult.ExceptionMessage =
					$"Exception caught while encrypting the message: {ex.Message}";
			}
			return asymmetricEncryptionResult;
		}

		public AsymmetricDecryptionResult DecryptWithFullKeyXml(byte[] cipherBytes, string fullKeyPairXml)
		{
			AsymmetricDecryptionResult asymmetricDecryptionResult = new AsymmetricDecryptionResult();
			try
			{
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
				rsaProvider.FromXmlString(fullKeyPairXml);
				byte[] decryptBytes = rsaProvider.Decrypt(cipherBytes, true);
				asymmetricDecryptionResult.DecryptedMessage = Encoding.UTF8.GetString(decryptBytes);
				asymmetricDecryptionResult.Success = true;
			}
			catch (Exception ex)
			{
				asymmetricDecryptionResult.ExceptionMessage =
					$"Exception caught while decrypting the cipher: {ex.Message}";
			}
			return asymmetricDecryptionResult;
		}

		public AsymmetricDecryptionResult DecryptWithCspProvider(byte[] cipherBytes, string keyContainerName)
		{
			AsymmetricDecryptionResult asymmetricDecryptionResult = new AsymmetricDecryptionResult();
			try
			{
				CspParameters cspParams = new CspParameters() { KeyContainerName = keyContainerName };
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams);
				byte[] decryptBytes = rsaProvider.Decrypt(cipherBytes, true);
				asymmetricDecryptionResult.DecryptedMessage = Encoding.UTF8.GetString(decryptBytes);
				asymmetricDecryptionResult.Success = true;
			}
			catch (Exception ex)
			{
				asymmetricDecryptionResult.ExceptionMessage =
					$"Exception caught while decrypting the cipher: {ex.Message}";
			}
			return asymmetricDecryptionResult;
		}

		public AsymmetricEncryptionResult EncryptWithCspProvider(string message, string keyContainerName)
		{
			AsymmetricEncryptionResult asymmetricEncryptionResult = new AsymmetricEncryptionResult();
			try
			{
				CspParameters cspParams = new CspParameters() { KeyContainerName = keyContainerName };
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams);
				byte[] encryptedAsBytes = rsaProvider.Encrypt(Encoding.UTF8.GetBytes(message), true);
				string encryptedAsBase64 = Convert.ToBase64String(encryptedAsBytes);
				asymmetricEncryptionResult.EncryptedAsBase64 = encryptedAsBase64;
				asymmetricEncryptionResult.EncryptedAsBytes = encryptedAsBytes;
				asymmetricEncryptionResult.Success = true;
			}
			catch (Exception ex)
			{
				asymmetricEncryptionResult.ExceptionMessage =
					$"Exception caught while encrypting the message: {ex.Message}";
			}
			return asymmetricEncryptionResult;
		}

		public AsymmetricKeyPairDeletionResult DeleteAsymmetricKeyPair(string containerName)
		{
			AsymmetricKeyPairDeletionResult asymmetricKeyPairDeletionResult = new AsymmetricKeyPairDeletionResult();
			try
			{
				CspParameters cspParams = new CspParameters() { KeyContainerName = containerName };
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams) { PersistKeyInCsp = false };
				rsaProvider.Clear();
				asymmetricKeyPairDeletionResult.Success = true;
			}
			catch (Exception ex)
			{
				asymmetricKeyPairDeletionResult.ExceptionMessage = ex.Message;
			}
			return asymmetricKeyPairDeletionResult;
		}

		public AsymmetricKeyPairPersistenceResult PersistNewAsymmetricKeyPair(int keySizeBits)
		{
			AsymmetricKeyPairPersistenceResult asymmetricKeyPairPersistenceResult = new AsymmetricKeyPairPersistenceResult();
			try
			{
				CspParameters cspParams = new CspParameters();
				string containerName = Guid.NewGuid().ToString();
				cspParams.KeyContainerName = containerName;
				cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(keySizeBits, cspParams)
					{ PersistKeyInCsp = true };
				CspKeyContainerInfo keyContainerInfo = new CspKeyContainerInfo(cspParams);
				string pathToMachineLevelAsymmetricKeysFolder = Path.Combine(
					Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
					@"Microsoft\Crypto\RSA\MachineKeys");
				asymmetricKeyPairPersistenceResult.KeyContainerName = keyContainerInfo.KeyContainerName;
				asymmetricKeyPairPersistenceResult.KeyStorageTopFolder = pathToMachineLevelAsymmetricKeysFolder;
				asymmetricKeyPairPersistenceResult.KeyStorageFileFullPath =
					Path.Combine(pathToMachineLevelAsymmetricKeysFolder, keyContainerInfo.UniqueKeyContainerName);
				asymmetricKeyPairPersistenceResult.Success = true;
			}
			catch (Exception ex)
			{
				asymmetricKeyPairPersistenceResult.ExceptionMessage = ex.Message;
			}
			return asymmetricKeyPairPersistenceResult;
		}
	}
}
