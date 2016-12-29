using System;
using System.Security.Cryptography;
using System.Text;

namespace HashingAlgos
{
	public class Hasher
    {
		public string CalculateMessageDigest(string originalMessage, HashAlgorithm hashAlgo)
		{
			return Convert.ToBase64String(hashAlgo.ComputeHash(Encoding.UTF8.GetBytes(originalMessage)));
		}
    }
}
