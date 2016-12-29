using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AsymmetricEncryption
{
	public interface IXmlBasedAsymmetricEncryptionService
	{
		AsymmetricKeyPairGenerationResult GenerateKeysAsXml(int keySizeBits);
		AsymmetricEncryptionResult EncryptWithPublicKeyXml(string message, string publicKeyAsXml);
		AsymmetricDecryptionResult DecryptWithFullKeyXml(byte[] cipherBytes, string fullKeyPairXml);
	}
}
