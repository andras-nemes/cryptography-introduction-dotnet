using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AsymmetricEncryption
{
	public class AsymmetricEncryptionResult : OperationResult
	{
		public byte[] EncryptedAsBytes { get; set; }
		public string EncryptedAsBase64 { get; set; }
	}
}
