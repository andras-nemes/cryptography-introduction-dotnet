using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashingAlgos
{
	public class HashingService : IHashingService
	{
		private readonly HashAlgorithm _hashAlgorithm;

		public HashingService(HashAlgorithm hashAlgorithm)
		{
			if (hashAlgorithm == null) throw new ArgumentNullException("Hash algorithm");
			_hashAlgorithm = hashAlgorithm;
		}
		public byte[] CalculateMessageDigest(string originalMessage)
		{
			return _hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(originalMessage));
		}

		public string GetHashAlgorithmDescription()
		{
			throw new NotImplementedException();
		}
	}
}
