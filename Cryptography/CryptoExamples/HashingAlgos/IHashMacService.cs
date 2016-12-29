using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HashingAlgos
{
	public interface IHashMacService
	{
		byte[] ComputeHashMac(byte[] bytesToHash, byte[] symmetricKey);
		string GetHashAlgorithmDescription();
	}

}
