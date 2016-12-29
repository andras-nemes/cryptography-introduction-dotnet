using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashingAlgos
{
	public class Sha256HashingService : IHashingService
	{
		public byte[] CalculateMessageDigest(string originalMessage)
		{
			SHA256 sha256 = SHA256.Create();
			return sha256.ComputeHash(Encoding.UTF8.GetBytes(originalMessage));
		}

		public string GetHashAlgorithmDescription()
		{
			return "SHA256";
		}
	}
}
