using AsymmetricEncryption;
using DigitalSignatures.Alternative;
using HashingAlgos;
using SymmetricEnryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace HybridEncryption
{
	public class SecretMessageReceiver : SecretMessageParticipant
	{
		private readonly Dictionary<Guid, AsymmetricKeyPairGenerationResult> _successfulKeyPairResults;

		public SecretMessageReceiver(IXmlBasedAsymmetricEncryptionService xmlBasedAsymmetricEncryptionService
			, ISymmetricEncryptionService symmetricEncryptionService, IHashMacService hashMacService, 
			IDigitalSignatureService digitalSignatureService)
			: base(xmlBasedAsymmetricEncryptionService, symmetricEncryptionService, 
				  hashMacService, digitalSignatureService)
		{			
			_successfulKeyPairResults = new Dictionary<Guid, AsymmetricKeyPairGenerationResult>();
		}

		public AsymmetricPublicKey GenerateOneTimeAsymmetricPublicKey()
		{
			int defaultAsymmetricKeySize = 2048;
			AsymmetricKeyPairGenerationResult asymmKeyPairGenerationResult =
				AsymmetricEncryptionService.GenerateKeysAsXml(defaultAsymmetricKeySize);
			if (asymmKeyPairGenerationResult.Success)
			{
				Guid guid = Guid.NewGuid();
				_successfulKeyPairResults[guid] = asymmKeyPairGenerationResult;
				return new AsymmetricPublicKey(guid, XDocument.Parse(asymmKeyPairGenerationResult.PublicKeyXml));
			}
			throw new CryptographicException(asymmKeyPairGenerationResult.ExceptionMessage);
		}

		public void ProcessIncomingMessage(EncryptedMessage encryptedMessage)
		{
			if (_successfulKeyPairResults.ContainsKey(encryptedMessage.AsymmetricKeyId))
			{
				byte[] encryptedSymmetricKey = Convert.FromBase64String(encryptedMessage.SymmetricKeyEncryptedBase64);
				AsymmetricDecryptionResult decryptSymmetricKey = AsymmetricEncryptionService.DecryptWithFullKeyXml
					(encryptedSymmetricKey,
					_successfulKeyPairResults[encryptedMessage.AsymmetricKeyId].PublicPrivateKeyPairXml);

				if (decryptSymmetricKey.Success)
				{
					string symmetricKeyBase64 = decryptSymmetricKey.DecryptedMessage;
					byte[] cipherText = Convert.FromBase64String(encryptedMessage.CipherTextBase64);

					byte[] hmacInMessage = Convert.FromBase64String(encryptedMessage.SecretMessageHmacBase64);
					byte[] hmacToCheckAgainst = HashMacService.ComputeHashMac(cipherText, Convert.FromBase64String(decryptSymmetricKey.DecryptedMessage));					
					bool hmacsEqual = hmacInMessage.SequenceEqual(hmacToCheckAgainst);
					if (!hmacsEqual)
					{
						throw new CryptographicException("Message hash mismatch!!!!!");
					}

					var signatureVerificationResult = DigitalSignatureService.VerifySignature(encryptedMessage.SignMessageResult);
					if (!signatureVerificationResult.SignaturesMatch)
					{
						throw new CryptographicException("Signature mismatch!!!");
					}
					byte[] iv = Convert.FromBase64String(encryptedMessage.InitializationVectorBase64);
					byte[] symmetricKey = Convert.FromBase64String(symmetricKeyBase64);
					string secretMessage = SymmetricEncryptionService.Decrypt(cipherText
						, symmetricKey, iv);
					Console.WriteLine($"Secret message receiver got the following message: {secretMessage}");
					_successfulKeyPairResults.Remove(encryptedMessage.AsymmetricKeyId);
				}
				else
				{
					throw new CryptographicException(decryptSymmetricKey.ExceptionMessage);
				}
			}
			else
			{
				throw new ArgumentException("No such key id found");
			}
		}
	}
}
