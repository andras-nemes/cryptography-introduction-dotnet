using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures.Alternative
{
	public interface IDigitalSignatureService
	{
		SignMessageResult SignMessage(byte[] hashToSign, int keySizeBits, string signingHashAlgorithm);
		DigitalSignatureVerificationResult VerifySignature(SignMessageResult signMessageResult);
	}
}
