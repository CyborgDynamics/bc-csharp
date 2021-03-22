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
	public class NTRUSigningKeyGenerationParameters : KeyGenerationParameters, ICloneable
	{
		public static int BASIS_TYPE_STANDARD = 0;
		public static int BASIS_TYPE_TRANSPOSE = 1;

		public static int KEY_GEN_ALG_RESULTANT = 0;
		public static int KEY_GEN_ALG_FLOAT = 1;
		/**
		* Gives 128 bits of security
		*/
		public static NTRUSigningKeyGenerationParameters APR2011_439 = new NTRUSigningKeyGenerationParameters(439, 2048, 146, 1, BASIS_TYPE_TRANSPOSE, 0.165, 490, 280, false, true, KEY_GEN_ALG_RESULTANT, new Sha256Digest());

		/**
		 * Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials
		 */
		public static NTRUSigningKeyGenerationParameters APR2011_439_PROD = new NTRUSigningKeyGenerationParameters(439, 2048, 9, 8, 5, 1, BASIS_TYPE_TRANSPOSE, 0.165, 490, 280, false, true, KEY_GEN_ALG_RESULTANT, new Sha256Digest());

		/**
		 * Gives 256 bits of security
		 */
		public static NTRUSigningKeyGenerationParameters APR2011_743 = new NTRUSigningKeyGenerationParameters(743, 2048, 248, 1, BASIS_TYPE_TRANSPOSE, 0.127, 560, 360, true, false, KEY_GEN_ALG_RESULTANT, new Sha512Digest());

		/**
		 * Like <code>APR2011_439</code>, this parameter set gives 256 bits of security but uses product-form polynomials
		 */
		public static NTRUSigningKeyGenerationParameters APR2011_743_PROD = new NTRUSigningKeyGenerationParameters(743, 2048, 11, 11, 15, 1, BASIS_TYPE_TRANSPOSE, 0.127, 560, 360, true, false, KEY_GEN_ALG_RESULTANT, new Sha512Digest());

		/**
		 * Generates key pairs quickly. Use for testing only.
		 */
		public static NTRUSigningKeyGenerationParameters TEST157 = new NTRUSigningKeyGenerationParameters(157, 256, 29, 1, BASIS_TYPE_TRANSPOSE, 0.38, 200, 80, false, false, KEY_GEN_ALG_RESULTANT, new Sha256Digest());
		/**
		 * Generates key pairs quickly. Use for testing only.
		 */
		public static NTRUSigningKeyGenerationParameters TEST157_PROD = new NTRUSigningKeyGenerationParameters(157, 256, 5, 5, 8, 1, BASIS_TYPE_TRANSPOSE, 0.38, 200, 80, false, false, KEY_GEN_ALG_RESULTANT, new Sha256Digest());


		public int N;
		public int q;
		public int d, d1, d2, d3, B;
		double beta;
		public double betaSq;
		double normBound;
		public double normBoundSq;
		public int signFailTolerance = 100;
		double keyNormBound;
		public double keyNormBoundSq;
		public bool primeCheck;   // true if N and 2N+1 are prime
		public int basisType;
		int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
		public bool sparse;   // whether to treat ternary polynomials as sparsely populated
		public int keyGenAlg;
		public IDigest hashAlg;
		public int polyType;

		/**
		 * Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
		 *
		 * @param N            number of polynomial coefficients
		 * @param q            modulus
		 * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
		 * @param B            number of perturbations
		 * @param basisType    whether to use the standard or transpose lattice
		 * @param beta         balancing factor for the transpose lattice
		 * @param normBound    maximum norm for valid signatures
		 * @param keyNormBound maximum norm for the ploynomials <code>F</code> and <code>G</code>
		 * @param primeCheck   whether <code>2N+1</code> is prime
		 * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
		 * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
		 * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
		 */
		public NTRUSigningKeyGenerationParameters(int N, int q, int d, int B, int basisType, double beta, double normBound, double keyNormBound, bool primeCheck, bool sparse, int keyGenAlg, IDigest hashAlg) : base(CryptoServicesRegistrar.GetSecureRandom(), N)
		{
			this.N = N;
			this.q = q;
			this.d = d;
			this.B = B;
			this.basisType = basisType;
			this.beta = beta;
			this.normBound = normBound;
			this.keyNormBound = keyNormBound;
			this.primeCheck = primeCheck;
			this.sparse = sparse;
			this.keyGenAlg = keyGenAlg;
			this.hashAlg = hashAlg;
			polyType = (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE;
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
		 * @param basisType    whether to use the standard or transpose lattice
		 * @param beta         balancing factor for the transpose lattice
		 * @param normBound    maximum norm for valid signatures
		 * @param keyNormBound maximum norm for the ploynomials <code>F</code> and <code>G</code>
		 * @param primeCheck   whether <code>2N+1</code> is prime
		 * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
		 * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
		 * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
		 */
		public NTRUSigningKeyGenerationParameters(int N, int q, int d1, int d2, int d3, int B, int basisType, double beta, double normBound, double keyNormBound, bool primeCheck, bool sparse, int keyGenAlg, IDigest hashAlg) : base(CryptoServicesRegistrar.GetSecureRandom(), N)
		{
			this.N = N;
			this.q = q;
			this.d1 = d1;
			this.d2 = d2;
			this.d3 = d3;
			this.B = B;
			this.basisType = basisType;
			this.beta = beta;
			this.normBound = normBound;
			this.keyNormBound = keyNormBound;
			this.primeCheck = primeCheck;
			this.sparse = sparse;
			this.keyGenAlg = keyGenAlg;
			this.hashAlg = hashAlg;
			polyType = (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT;
			init();
		}

		private void init()
		{
			betaSq = beta * beta;
			normBoundSq = normBound * normBound;
			keyNormBoundSq = keyNormBound * keyNormBound;
		}

		/**
		 * Reads a parameter set from an input stream.
		 *
		 * @param is an input stream
		 * @throws java.io.IOException
		 */
		public NTRUSigningKeyGenerationParameters(Stream stream) : base(CryptoServicesRegistrar.GetSecureRandom(), 0)
		{
			BinaryReader dis = new BinaryReader(stream);
			N = dis.ReadInt32();
			q = dis.ReadInt32();
			d = dis.ReadInt32();
			d1 = dis.ReadInt32();
			d2 = dis.ReadInt32();
			d3 = dis.ReadInt32();
			B = dis.ReadInt32();
			basisType = dis.ReadInt32();
			beta = dis.ReadDouble();
			normBound = dis.ReadDouble();
			keyNormBound = dis.ReadDouble();
			signFailTolerance = dis.ReadInt32();
			primeCheck = dis.ReadBoolean();
			sparse = dis.ReadBoolean();
			bitsF = dis.ReadInt32();
			keyGenAlg = dis.ReadInt32();
			string alg = dis.ReadString();
			if ("SHA-512".Equals(alg))
			{
				hashAlg = new Sha512Digest();
			}
			else if ("SHA-256".Equals(alg))
			{
				hashAlg = new Sha256Digest();
			}
			polyType = dis.ReadInt32();
			init();
		}

		/**
		 * Writes the parameter set to an output stream
		 *
		 * @param os an output stream
		 * @throws java.io.IOException
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
			dos.Write(basisType);
			dos.Write(beta);
			dos.Write(normBound);
			dos.Write(keyNormBound);
			dos.Write(signFailTolerance);
			dos.Write(primeCheck);
			dos.Write(sparse);
			dos.Write(bitsF);
			dos.Write(keyGenAlg);
			dos.Write(hashAlg.AlgorithmName);
			dos.Write(polyType);
		}

		public NTRUSigningParameters getSigningParameters()
		{
			return new NTRUSigningParameters(N, q, d, B, beta, normBound, hashAlg);
		}

		public object Clone()
		{
			if (polyType == (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
			{
				return new NTRUSigningKeyGenerationParameters(N, q, d, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
			}
			else
			{
				return new NTRUSigningKeyGenerationParameters(N, q, d1, d2, d3, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
			}
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + B;
			result = prime * result + N;
			result = prime * result + basisType;
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
			result = prime * result + keyGenAlg;
			temp = BitConverter.DoubleToInt64Bits(keyNormBound);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			temp = BitConverter.DoubleToInt64Bits(keyNormBoundSq);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			temp = BitConverter.DoubleToInt64Bits(normBound);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			temp = BitConverter.DoubleToInt64Bits(normBoundSq);
			result = prime * result + (int)(temp ^ (temp.UnsignedRightShift(32)));
			result = prime * result + polyType;
			result = prime * result + (primeCheck ? 1231 : 1237);
			result = prime * result + q;
			result = prime * result + signFailTolerance;
			result = prime * result + (sparse ? 1231 : 1237);
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
			if (!(obj.GetType() == typeof(NTRUSigningKeyGenerationParameters)))
	
		{
				return false;
			}
			NTRUSigningKeyGenerationParameters other = (NTRUSigningKeyGenerationParameters)obj;
			if (B != other.B)
			{
				return false;
			}
			if (N != other.N)
			{
				return false;
			}
			if (basisType != other.basisType)
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
			if (keyGenAlg != other.keyGenAlg)
			{
				return false;
			}
			if (BitConverter.DoubleToInt64Bits(keyNormBound) != BitConverter.DoubleToInt64Bits(other.keyNormBound))
			{
				return false;
			}
			if (BitConverter.DoubleToInt64Bits(keyNormBoundSq) != BitConverter.DoubleToInt64Bits(other.keyNormBoundSq))
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
			if (polyType != other.polyType)
			{
				return false;
			}
			if (primeCheck != other.primeCheck)
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
			if (sparse != other.sparse)
			{
				return false;
			}
			return true;
		}

		public override string ToString()
		{
			string format = "{0:0.00}";

			StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);
			if (polyType == (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
			{
				output.Append(" polyType=SIMPLE d=" + d);
			}
			else
			{
				output.Append(" polyType=PRODUCT d1=" + d1 + " d2=" + d2 + " d3=" + d3);
			}
			output.Append(" B=" + B + " basisType=" + basisType + " beta=" + beta.ToString(format) +
				" normBound=" + normBound.ToString() + " keyNormBound=" + keyNormBound.ToString() +
				" prime=" + primeCheck + " sparse=" + sparse + " keyGenAlg=" + keyGenAlg + " hashAlg=" + hashAlg + ")");
			return output.ToString();
		}
	}
}