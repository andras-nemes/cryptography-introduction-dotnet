using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using RandomNumberGenerator;

namespace HashingAlgos
{
	public class PKCS
	{
		public HashWithSaltResult HashPasswordWithPkcs(string plainPassword, int roundOfHashIterations, int saltLengthBytes)
		{
			RNG rng = new RNG();
			byte[] saltBytes = rng.GenerateRandomCryptographicBytes(saltLengthBytes);
			Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(plainPassword, saltBytes, roundOfHashIterations);
			byte[] derivedBytes = pbkdf.GetBytes(32);
			return new HashWithSaltResult(Convert.ToBase64String(saltBytes), Convert.ToBase64String(derivedBytes));
		}
	}
}
