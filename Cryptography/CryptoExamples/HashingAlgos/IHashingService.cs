using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HashingAlgos
{
	public interface IHashingService
	{
		byte[] CalculateMessageDigest(string originalMessage);
		string GetHashAlgorithmDescription();
	}
}
