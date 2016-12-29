using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashingAlgos
{
	public class HmacSha256Service : IHashMacService
	{
		public byte[] ComputeHashMac(byte[] bytesToHash, byte[] symmetricKey)
		{
			HMACSHA256 hmac = new HMACSHA256(symmetricKey);
			byte[] hmacHash = hmac.ComputeHash(bytesToHash);
			return hmacHash;
		}
		public string GetHashAlgorithmDescription()
		{
			return "SHA256";
		}
	}
}
