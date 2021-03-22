using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru { 


public class NTRUEncryptionKeyParameters : AsymmetricKeyParameter
{
    protected NTRUEncryptionParameters parameters;

    public NTRUEncryptionKeyParameters(bool privateKey, NTRUEncryptionParameters parameters) : base(privateKey)
    {
        this.parameters = parameters;
    }

    public NTRUEncryptionParameters GetParameters()
    {
        return parameters;
    }
}
}