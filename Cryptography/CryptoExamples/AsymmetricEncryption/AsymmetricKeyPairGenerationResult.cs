using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AsymmetricEncryption
{
	public class AsymmetricKeyPairGenerationResult : OperationResult
	{
		public string PublicKeyXml { get; set; }
		public string PublicPrivateKeyPairXml { get; set; }
		public AsymmetricAlgorithm AsymmetricAlgorithmImplementation { get; set; }
	}
}
