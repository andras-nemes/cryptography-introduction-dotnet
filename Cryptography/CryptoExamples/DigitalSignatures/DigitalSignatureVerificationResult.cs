using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures
{
	public class DigitalSignatureVerificationResult : OperationResult
	{
		public bool SignaturesMatch { get; set; }
	}
}
