using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Pqc.Math.Ntru.Util;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{

	/**
	 * A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
	 */
	public class NTRUSigningParameters : ICloneable
	{
		public int N;
		public int q;
		public int d, d1, d2, d3, B;
		double beta;
		public double betaSq;
		double normBound;
		public double normBoundSq;
		public int signFailTolerance = 100;
		int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
		public IDigest hashAlg;

		/**
		 * Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
		 *
		 * @param N            number of polynomial coefficients
		 * @param q            modulus
		 * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
		 * @param B            number of perturbations
		 * @param beta         balancing factor for the transpose lattice
		 * @param normBound    maximum norm for valid signatures
		 * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
		 */
		public NTRUSigningParameters(int N, int q, int d, int B, double beta, double normBound, IDigest hashAlg)
		{
			this.N = N;
			this.q = q;
			this.d = d;
			this.B = B;
			this.beta = beta;
			this.normBound = normBound;
			this.hashAlg = hashAlg;
			init();
		}

		/**
		 * Constructs a parameter set that uses product-form private keys (i.e. <code>polyType=PRODUCT</code>).
		 *
		 * @param N            number of polynomial coefficients
		 * @param q            modulus
		 * @param d1           number of -1's in the private polynomials <code>f</code> and <code>g</code>
		 * @param d2           number of -1's in the private polynomials <code>f</code> and <code>g</code>
		 * @param d3           number of -1's in the private polynomials <code>f</code> and <code>g</code>
		 * @param B            number of perturbations
		 * @param beta         balancing factor for the transpose lattice
		 * @param normBound    maximum norm for valid signatures
		 * @param keyNormBound maximum norm for the ploynomials <code>F</code> and <code>G</code>
		 * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
		 */
		public NTRUSigningParameters(int N, int q, int d1, int d2, int d3, int B, double beta, double normBound, double keyNormBound, IDigest hashAlg)
		{
			this.N = N;
			this.q = q;
			this.d1 = d1;
			this.d2 = d2;
			this.d3 = d3;
			this.B = B;
			this.beta = beta;
			this.normBound = normBound;
			this.hashAlg = hashAlg;
			init();
		}

		private void init()
		{
			betaSq = beta * beta;
			normBoundSq = normBound * normBound;
		}

		/**
		 * Reads a parameter set from an input stream.
		 *
		 * @param is an input stream
		 * @throws IOException
		 */
		public NTRUSigningParameters(Stream stream)
		{
			BinaryReader dis = new BinaryReader(stream);
			N = dis.ReadInt32();
			q = dis.ReadInt32();
			d = dis.ReadInt32();
			d1 = dis.ReadInt32();
			d2 = dis.ReadInt32();
			d3 = dis.ReadInt32();
			B = dis.ReadInt32();
			beta = dis.ReadDouble();
			normBound = dis.ReadDouble();
			signFailTolerance = dis.ReadInt32();
			bitsF = dis.ReadInt32();
			String alg = dis.ReadString();
			if ("SHA-512".Equals(alg))
			{
				hashAlg = new Sha512Digest();
			}
			else if ("SHA-256".Equals(alg))
			{
				hashAlg = new Sha256Digest();
			}
			init();
		}

		/**
		 * Writes the parameter set to an output stream
		 *
		 * @param os an output stream
		 * @throws IOException
		 */
		public void writeTo(Stream os)

		{
			BinaryWriter dos = new BinaryWriter(os);
			dos.Write(N);
			dos.Write(q);
			dos.Write(d);
			dos.Write(d1);
			dos.Write(d2);
			dos.Write(d3);
			dos.Write(B);
			dos.Write(beta);
			dos.Write(normBound);
			dos.Write(signFailTolerance);
			dos.Write(bitsF);
			dos.Write(hashAlg.AlgorithmName);
		}

		public object Clone()
		{
			return new NTRUSigningParameters(N, q, d, B, beta, normBound, hashAlg);
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + B;
			result = prime * result + N;
			long temp;
			temp = BitConverter.DoubleToInt64Bits(beta);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			temp = BitConverter.DoubleToInt64Bits(betaSq);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			result = prime * result + bitsF;
			result = prime * result + d;
			result = prime * result + d1;
			result = prime * result + d2;
			result = prime * result + d3;
			result = prime * result + ((hashAlg == null) ? 0 : hashAlg.AlgorithmName.GetHashCode());
			temp = BitConverter.DoubleToInt64Bits(normBound);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			temp = BitConverter.DoubleToInt64Bits(normBoundSq);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			result = prime * result + q;
			result = prime * result + signFailTolerance;
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
			if (!(obj.GetType() == typeof(NTRUSigningParameters)))
        {
				return false;
			}
			NTRUSigningParameters other = (NTRUSigningParameters)obj;
			if (B != other.B)
			{
				return false;
			}
			if (N != other.N)
			{
				return false;
			}
			if (BitConverter.DoubleToInt64Bits(beta) != BitConverter.DoubleToInt64Bits(other.beta))
			{
				return false;
			}
			if (BitConverter.DoubleToInt64Bits(betaSq) != BitConverter.DoubleToInt64Bits(other.betaSq))
			{
				return false;
			}
			if (bitsF != other.bitsF)
			{
				return false;
			}
			if (d != other.d)
			{
				return false;
			}
			if (d1 != other.d1)
			{
				return false;
			}
			if (d2 != other.d2)
			{
				return false;
			}
			if (d3 != other.d3)
			{
				return false;
			}
			if (hashAlg == null)
			{
				if (other.hashAlg != null)
				{
					return false;
				}
			}
			else if (!hashAlg.AlgorithmName.Equals(other.hashAlg.AlgorithmName))
			{
				return false;
			}
			if (BitConverter.DoubleToInt64Bits(normBound) != BitConverter.DoubleToInt64Bits(other.normBound))
			{
				return false;
			}
			if (BitConverter.DoubleToInt64Bits(normBoundSq) != BitConverter.DoubleToInt64Bits(other.normBoundSq))
			{
				return false;
			}
			if (q != other.q)
			{
				return false;
			}
			if (signFailTolerance != other.signFailTolerance)
			{
				return false;
			}

			return true;
		}

		public override string ToString()
		{
			string format = "{0:0.00}";

			StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);

			output.Append(" B=" + B + " beta=" + beta.ToString(format) +
				" normBound=" + normBound.ToString(format) +
				" hashAlg=" + hashAlg + ")");
			return output.ToString();
		}
	}
}