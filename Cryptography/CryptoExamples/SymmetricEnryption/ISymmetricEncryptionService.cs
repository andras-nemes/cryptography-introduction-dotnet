using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SymmetricEnryption
{
	public interface ISymmetricEncryptionService
	{
		SymmetricEncryptionResult Encrypt(string messageToEncrypt, int symmetricKeyLengthBits);
		string Decrypt(byte[] cipherTextBytes, byte[] key, byte[] iv);
	}
}
