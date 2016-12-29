using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures
{
	public class SignMessageResult : OperationResult
	{
		public byte[] HashedMessage { get; set; }
		public byte[] Signature { get; set; }
		public string PublicSigningKeyXml { get; set; }
		public string SigningHashAlgorithm { get; set; }
	}
}
