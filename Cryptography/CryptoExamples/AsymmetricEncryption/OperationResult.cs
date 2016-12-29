using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AsymmetricEncryption
{
	public abstract class OperationResult
	{
		public bool Success { get; set; }
		public string ExceptionMessage { get; set; }
	}
}
