using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures.Alternative
{
	public class RsaSigitalSignatureService : IDigitalSignatureService
	{
		public SignMessageResult SignMessage(byte[] hashToSign, int keySizeBits, string signingHashAlgorithm)
		{
			SignMessageResult result = new SignMessageResult();
			try
			{
				RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(keySizeBits);
				string publicKeyXml = rsaProvider.ToXmlString(false);
				RSAPKCS1SignatureFormatter signatureFormatter =
					new RSAPKCS1SignatureFormatter(rsaProvider);
				signatureFormatter.SetHashAlgorithm(signingHashAlgorithm);
				byte[] signature = signatureFormatter.CreateSignature(hashToSign);
				result.PublicSigningKeyXml = publicKeyXml;
				result.Success = true;
				result.HashedMessage = hashToSign;
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
