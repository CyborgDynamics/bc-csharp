using System.IO;

using Org.BouncyCastle.Pqc.Math.Ntru.Polynomial;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{

	/**
	 * A NtruEncrypt public key is essentially a polynomial named <code>h</code>.
	 */
	public class NTRUEncryptionPublicKeyParameters : NTRUEncryptionKeyParameters
	{
		public IntegerPolynomial h;

		/**
		 * Constructs a new public key from a polynomial
		 *
		 * @param h      the polynomial <code>h</code> which determines the key
		 * @param params the NtruEncrypt parameters to use
		 */
		public NTRUEncryptionPublicKeyParameters(IntegerPolynomial h, NTRUEncryptionParameters parameters) : base(false, parameters)
		{
			this.h = h;
		}

		/**
         * Converts a byte array to a polynomial <code>h</code> and constructs a new public key
         *
         * @param b      an encoded polynomial
         * @param params the NtruEncrypt parameters to use
         * @see #getEncoded()
         */
		public NTRUEncryptionPublicKeyParameters(byte[] b, NTRUEncryptionParameters parameters) : base(false, parameters)
		{

			h = IntegerPolynomial.FromBinary(b, parameters.N, parameters.q);
		}

		/**
		 * Reads a polynomial <code>h</code> from an input stream and constructs a new public key
		 *
		 * @param is     an input stream
		 * @param params the NtruEncrypt parameters to use
		 * @see #writeTo(OutputStream)
		 */
		public NTRUEncryptionPublicKeyParameters(Stream stream, NTRUEncryptionParameters parameters) : base(false, parameters)
		{
			h = IntegerPolynomial.FromBinary(stream, parameters.N, parameters.q);
		}

		/**
		 * Converts the key to a byte array
		 *
		 * @return the encoded key
		 * @see #NTRUEncryptionPublicKeyParameters(byte[], NTRUEncryptionParameters)
		 */
		public byte[] GetEncoded()
		{
			return h.ToBinary(parameters.q);
		}

		/**
		 * Writes the key to an output stream
		 *
		 * @param os an output stream
		 * @throws IOException
		 * @see #NTRUEncryptionPublicKeyParameters(InputStream, NTRUEncryptionParameters)
		 */
		public void WriteTo(Stream os)
		{
			BinaryWriter bw = new BinaryWriter(os);
			bw.Write(GetEncoded());
		}

		public override int GetHashCode()
		{
			int prime = 31;
			int result = 1;
			result = prime * result + ((h == null) ? 0 : h.GetHashCode());
			result = prime * result + ((parameters == null) ? 0 : parameters.GetHashCode());
			return result;
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (obj == null)
			{
				return false;
			}
			if (!(obj.GetType() == typeof(NTRUEncryptionPublicKeyParameters)))
			{
				return false;
			}
			NTRUEncryptionPublicKeyParameters other = (NTRUEncryptionPublicKeyParameters)obj;
			if (h == null)
			{
				if (other.h != null)
				{
					return false;
				}
			}
			else if (!h.Equals(other.h))
			{
				return false;
			}
			if (parameters == null)
			{
				if (other.parameters != null)
				{
					return false;
				}
			}
			else if (!parameters.Equals(other.parameters))
			{
				return false;
			}
			return true;
		}
	}
}