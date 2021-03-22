using System;
using System.IO;

using Org.BouncyCastle.Pqc.Math.Ntru.Polynomial;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{

	/**
	 * A NtruEncrypt private key is essentially a polynomial named <code>f</code>
	 * which takes different forms depending on whether product-form polynomials are used,
	 * and on <code>fastP</code><br>
	 * The inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
	 */
	public class NTRUEncryptionPrivateKeyParameters : NTRUEncryptionKeyParameters
	{
		public IPolynomial t;
		public IntegerPolynomial fp;
		public IntegerPolynomial h;
		/**
		 * Constructs a new private key from a polynomial
		 *
		 * @param h the public polynomial for the key.
		 * @param t      the polynomial which determines the key: if <code>fastFp=true</code>, <code>f=1+3t</code>; otherwise, <code>f=t</code>
		 * @param fp     the inverse of <code>f</code>
		 * @param params the NtruEncrypt parameters to use
		 */
		public NTRUEncryptionPrivateKeyParameters(IntegerPolynomial h, IPolynomial t, IntegerPolynomial fp, NTRUEncryptionParameters parameters) : base(true, parameters)
		{
			this.h = h;
			this.t = t;
			this.fp = fp;
		}

		/**
		 * Converts a byte array to a polynomial <code>f</code> and constructs a new private key
		 *
		 * @param b      an encoded polynomial
		 * @param params the NtruEncrypt parameters to use
		 * @see #getEncoded()
		 */
		public NTRUEncryptionPrivateKeyParameters(byte[] b, NTRUEncryptionParameters parameters) : this(new MemoryStream(b), parameters)
		{

		}

		/**
		 * Reads a polynomial <code>f</code> from an input stream and constructs a new private key
		 *
		 * @param is     an input stream
		 * @param params the NtruEncrypt parameters to use
		 * @see #writeTo(OutputStream)
		 */
		public NTRUEncryptionPrivateKeyParameters(Stream stream, NTRUEncryptionParameters parameters) : base(true, parameters)
		{

			if (parameters.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
			{
				int N = parameters.N;
				int df1 = parameters.df1;
				int df2 = parameters.df2;
				int df3Ones = parameters.df3;
				int df3NegOnes = parameters.fastFp ? parameters.df3 : parameters.df3 - 1;
				h = IntegerPolynomial.FromBinary(stream, parameters.N, parameters.q);
				t = ProductFormPolynomial.FromBinary(stream, N, df1, df2, df3Ones, df3NegOnes);
			}
			else
			{
				h = IntegerPolynomial.FromBinary(stream, parameters.N, parameters.q);
				IntegerPolynomial fInt = IntegerPolynomial.FromBinary3Tight(stream, parameters.N);
				t = parameters.sparse ? new SparseTernaryPolynomial(fInt) : (IPolynomial)new DenseTernaryPolynomial(fInt);
			}

			Init();
		}

		/**
		 * Initializes <code>fp</code> from t.
		 */
		private void Init()
		{
			if (parameters.fastFp)
			{
				fp = new IntegerPolynomial(parameters.N);
				fp.coeffs[0] = 1;
			}
			else
			{
				fp = t.ToIntegerPolynomial().InvertF3();
			}
		}

		/**
		 * Converts the key to a byte array
		 *
		 * @return the encoded key
		 * @see #NTRUEncryptionPrivateKeyParameters(byte[], NTRUEncryptionParameters)
		 */
		public byte[] GetEncoded()
		{
			byte[] hBytes = h.ToBinary(parameters.q);
			byte[] tBytes;

			if (t.GetType() == typeof(ProductFormPolynomial))
        {
				tBytes = ((ProductFormPolynomial)t).ToBinary();
			}

		else
			{
				tBytes = t.ToIntegerPolynomial().ToBinary3Tight();
			}

			byte[] res = new byte[hBytes.Length + tBytes.Length];

			Array.Copy(hBytes, 0, res, 0, hBytes.Length);
			Array.Copy(tBytes, 0, res, hBytes.Length, tBytes.Length);

			return res;
		}

		/**
		 * Writes the key to an output stream
		 *
		 * @param os an output stream
		 * @throws IOException
		 * @see #NTRUEncryptionPrivateKeyParameters(InputStream, NTRUEncryptionParameters)
		 */
		public void WriteTo(Stream os)
		{
			BinaryWriter bw = new BinaryWriter(os);
			bw.Write(GetEncoded());
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + ((parameters == null) ? 0 : parameters.GetHashCode());
			result = prime * result + ((t == null) ? 0 : t.GetHashCode());
			result = prime * result + ((h == null) ? 0 : h.GetHashCode());
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
			if (!(obj.GetType() == typeof(NTRUEncryptionPrivateKeyParameters)))
			{
				return false;
			}
			NTRUEncryptionPrivateKeyParameters other = (NTRUEncryptionPrivateKeyParameters)obj;
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
			if (t == null)
			{
				if (other.t != null)
				{
					return false;
				}
			}
			else if (!t.Equals(other.t))
			{
				return false;
			}
			if (!h.Equals(other.h))
			{
				return false;
			}
			return true;
		}
	}
}