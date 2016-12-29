using AsymmetricEncryption;
using DigitalSignatures.Alternative;
using HashingAlgos;
using SymmetricEnryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HybridEncryption
{
	public abstract class SecretMessageParticipant
	{
		private readonly IXmlBasedAsymmetricEncryptionService _xmlBasedAsymmetricEncryptionService;
		private readonly ISymmetricEncryptionService _symmetricEncryptionService;
		private readonly IHashMacService _hashMacService;
		private readonly IDigitalSignatureService _digitalSignatureService;

		public SecretMessageParticipant(IXmlBasedAsymmetricEncryptionService xmlBasedAsymmetricEncryptionService
			, ISymmetricEncryptionService symmetricEncryptionService, IHashMacService hashMacService,
			IDigitalSignatureService digitalSignatureService)
		{
			if (xmlBasedAsymmetricEncryptionService == null) throw new ArgumentNullException("XmlBasedAsymmetricEncryptionService");
			if (symmetricEncryptionService == null) throw new ArgumentNullException("SymmetricEncryptionService");
			if (hashMacService == null) throw new ArgumentNullException("HashMacService");
			if (digitalSignatureService == null) throw new ArgumentNullException("DigitalSignatureService");
			AsymmetricEncryptionService = xmlBasedAsymmetricEncryptionService;
			SymmetricEncryptionService = symmetricEncryptionService;
			HashMacService = hashMacService;
			DigitalSignatureService = digitalSignatureService;
		}

		public IXmlBasedAsymmetricEncryptionService AsymmetricEncryptionService { get; }		
		public ISymmetricEncryptionService SymmetricEncryptionService { get; }
		public IHashMacService HashMacService { get; }
		public IDigitalSignatureService DigitalSignatureService { get; }
	}
}
