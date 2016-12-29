using AsymmetricEncryption;
using DigitalSignatures.Alternative;
using HashingAlgos;
using SymmetricEnryption;
using System;

namespace HybridEncryption
{
	public class SecretMessageSender : SecretMessageParticipant
	{
		private readonly SecretMessageReceiver _secretMessageReceiver;		
		private readonly string _extremelyConfidentialMessage;

		public SecretMessageSender(SecretMessageReceiver secretMessageReceiver, 
			ISymmetricEncryptionService symmetricEncryptionService, 
			IXmlBasedAsymmetricEncryptionService xmlBasedAsymmetricEncryptionService,
			IHashMacService hashMacService, IDigitalSignatureService digitalSignatureService)
			: base(xmlBasedAsymmetricEncryptionService, symmetricEncryptionService,
					hashMacService, digitalSignatureService)
		{
			if (secretMessageReceiver == null) throw new ArgumentNullException("SecretMessageReceiver");			
			_secretMessageReceiver = secretMessageReceiver;			
			_extremelyConfidentialMessage = "My new invention will save the world.";
		}

		public void Start()
		{
			int defaultSymmetricKeySize = 256;
			AsymmetricPublicKey oneTimeAsymmetricPublicKey = _secretMessageReceiver.GenerateOneTimeAsymmetricPublicKey();
			SymmetricEncryptionResult symmetricEncryptionOfSecretMessage = 
				SymmetricEncryptionService.Encrypt(_extremelyConfidentialMessage, defaultSymmetricKeySize);
			string symmetricKeyBase64 = Convert.ToBase64String(symmetricEncryptionOfSecretMessage.SymmetricKey);
			string ivBase64 = Convert.ToBase64String(symmetricEncryptionOfSecretMessage.IV);

			byte[] hmacHash = HashMacService
				.ComputeHashMac(symmetricEncryptionOfSecretMessage.Cipher, symmetricEncryptionOfSecretMessage.SymmetricKey);
			var signatureResult = DigitalSignatureService.SignMessage(hmacHash, 2048, HashMacService.GetHashAlgorithmDescription());
			if (signatureResult.Success)
			{
				string hmacHashBase64 = Convert.ToBase64String(hmacHash);

				AsymmetricEncryptionResult asymmetricallyEncryptedSymmetricKeyResult =
					AsymmetricEncryptionService.EncryptWithPublicKeyXml(symmetricKeyBase64, oneTimeAsymmetricPublicKey.PublicKeyXml.ToString());

				EncryptedMessage encryptedMessage = new EncryptedMessage(asymmetricallyEncryptedSymmetricKeyResult.EncryptedAsBase64
					, ivBase64, symmetricEncryptionOfSecretMessage.CipherBase64, oneTimeAsymmetricPublicKey.PublicKeyId, 
					hmacHashBase64, signatureResult);

				_secretMessageReceiver.ProcessIncomingMessage(encryptedMessage);
			}
			else
			{
				Console.WriteLine(signatureResult.ExceptionMessage);
			}
		}
	}
}
