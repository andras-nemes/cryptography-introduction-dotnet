using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures
{
	public interface IDigitalSignatureService
	{
		SignMessageResult SignMessage(string message);
		DigitalSignatureVerificationResult VerifySignature(SignMessageResult signMessageResult);
	}
}
