using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace HybridEncryption
{
	public class AsymmetricPublicKey
	{
		public AsymmetricPublicKey(Guid publicKeyId, XDocument publicKeyXml)
		{
			PublicKeyId = publicKeyId;
			PublicKeyXml = publicKeyXml;
		}
		
		public Guid PublicKeyId { get; }
		public XDocument PublicKeyXml { get; }
	}
}
