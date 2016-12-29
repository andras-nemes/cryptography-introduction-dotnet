using DigitalSignatures;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HybridEncryption
{
	public class EncryptedMessage
	{
		public EncryptedMessage(string symmetricKeyEncryptedBase64, string initializationVectorBase64
			, string cipherTextBase64, Guid asymmetricKeyId, string secretMessageHmacBase64, SignMessageResult signMessageResult)
		{
			SymmetricKeyEncryptedBase64 = symmetricKeyEncryptedBase64;
			InitializationVectorBase64 = initializationVectorBase64;
			CipherTextBase64 = cipherTextBase64;
			AsymmetricKeyId = asymmetricKeyId;
			SecretMessageHmacBase64 = secretMessageHmacBase64;
			SignMessageResult = signMessageResult;
		}

		public string SymmetricKeyEncryptedBase64 { get; }
		public string InitializationVectorBase64 { get; }		
		public string CipherTextBase64 { get; }
		public Guid AsymmetricKeyId { get; }
		public string SecretMessageHmacBase64 { get; }
		public SignMessageResult SignMessageResult { get; set; }
	}
}
