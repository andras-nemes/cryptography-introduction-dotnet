using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SymmetricEnryption
{
	public class SymmetricEncryptionResult : OperationResult
	{
		public byte[] Cipher { get; set; }
		public string CipherBase64 { get; set; }
		public byte[] IV { get; set; }
		public byte[] SymmetricKey { get; set; }		
	}
}
