using AsymmetricEncryption;
using HashingAlgos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures
{
	public class RsaDigitalSignatureService : IDigitalSignatureService
	{
		private readonly IHashingService _hashingService;

		public RsaDigitalSignatureService(IHashingService hashingService)
		{			
			if (hashingService == null) throw new ArgumentNullException("Hashing service");
			_hashingService = hashingService;
		}

		public SignMessageResult SignMessage(string message)
		{
			SignMessageResult result = new SignMessageResult();
			try
			{
				int rsaKeySizeBits = 2048;
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(rsaKeySizeBits);
				string publicKeyXml = rsaProvider.ToXmlString(false);
				RSAPKCS1SignatureFormatter signatureFormatter =
					new RSAPKCS1SignatureFormatter(rsaProvider);
				string signingHashAlgorithm = _hashingService.GetHashAlgorithmDescription();
				signatureFormatter.SetHashAlgorithm(signingHashAlgorithm);
				byte[] hashedMessage = _hashingService.CalculateMessageDigest(message);
				byte[] signature = signatureFormatter.CreateSignature(hashedMessage);
				result.PublicSigningKeyXml = publicKeyXml;
				result.Success = true;
				result.HashedMessage = hashedMessage;
				result.Signature = signature;
				result.SigningHashAlgorithm = signingHashAlgorithm;
			}
			catch (Exception ex)
			{
				result.ExceptionMessage = ex.Message;
			}

			return result;
		}

		public DigitalSignatureVerificationResult VerifySignature(SignMessageResult signMessageResult)
		{			
			DigitalSignatureVerificationResult result = new DigitalSignatureVerificationResult();
			try
			{
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
				rsaProvider.FromXmlString(signMessageResult.PublicSigningKeyXml);
				RSAPKCS1SignatureDeformatter signatureDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
				signatureDeformatter.SetHashAlgorithm(signMessageResult.SigningHashAlgorithm);
				bool signatureOk = signatureDeformatter.VerifySignature(signMessageResult.HashedMessage, 
					signMessageResult.Signature);
				result.SignaturesMatch = signatureOk;
				result.Success = true;
			}
			catch (Exception ex)
			{
				result.ExceptionMessage = ex.Message;
			}
			return result;
		}
	}
}
