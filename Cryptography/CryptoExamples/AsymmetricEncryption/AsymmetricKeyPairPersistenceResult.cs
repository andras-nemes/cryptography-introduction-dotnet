using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AsymmetricEncryption
{
	public class AsymmetricKeyPairPersistenceResult : OperationResult
	{
		public string KeyContainerName { get; set; }
		public string KeyStorageFileFullPath { get; set; }
		public string KeyStorageTopFolder { get; set; }
	}
}
