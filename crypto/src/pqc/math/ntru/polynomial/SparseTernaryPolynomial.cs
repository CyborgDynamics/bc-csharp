using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Math.Ntru.Util;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{

	/**
	 * A <code>TernaryPolynomial</code> with a "low" number of nonzero coefficients.
	 */
	public class SparseTernaryPolynomial : ITernaryPolynomial
	{
		/**
		 * Number of bits to use for each coefficient. Determines the upper bound for <code>N</code>.
		 */
		private static int BITS_PER_INDEX = 11;

		private int N;
		private int[] Ones;
		private int[] NegOnes;

		/**
		 * Constructs a new polynomial.
		 *
		 * @param N       total number of coefficients including zeros
		 * @param ones    indices of coefficients equal to 1
		 * @param negOnes indices of coefficients equal to -1
		 */
		SparseTernaryPolynomial(int n, int[] ones, int[] negOnes)
		{
			N = n;
			Ones = ones;
			NegOnes = negOnes;
		}

		/**
		 * Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		 * independent of each other.
		 *
		 * @param intPoly the original polynomial
		 */
		public SparseTernaryPolynomial(IntegerPolynomial intPoly) : this(intPoly.coeffs)
		{
		}

		/**
		 * Constructs a new <code>SparseTernaryPolynomial</code> with a given set of coefficients.
		 *
		 * @param coeffs the coefficients
		 */
		public SparseTernaryPolynomial(int[] coeffs)
		{
			N = coeffs.Length;
			Ones = new int[N];
			NegOnes = new int[N];
			int onesIdx = 0;
			int negOnesIdx = 0;
			for (int i = 0; i < N; i++)
			{
				int c = coeffs[i];
				switch (c)
				{
					case 1:
						Ones[onesIdx++] = i;
						break;
					case -1:
						NegOnes[negOnesIdx++] = i;
						break;
					case 0:
						break;
					default:
						throw new InvalidOperationException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
				}
			}
			int[] tempOnes = new int[onesIdx];
			int[] tempNegOnes = new int[negOnesIdx];
			Array.Copy(Ones, tempOnes, onesIdx);
			Array.Copy(NegOnes, tempNegOnes, negOnesIdx);
			Ones = tempOnes;
			NegOnes = tempNegOnes;
		}

		/**
		 * Decodes a byte array encoded with {@link #toBinary()} to a ploynomial.
		 *
		 * @param is         an input stream containing an encoded polynomial
		 * @param N          number of coefficients including zeros
		 * @param numOnes    number of coefficients equal to 1
		 * @param numNegOnes number of coefficients equal to -1
		 * @return the decoded polynomial
		 * @throws IOException
		 */
		public static SparseTernaryPolynomial FromBinary(Stream stream, int N, int numOnes, int numNegOnes)
		{
			int maxIndex = 1 << BITS_PER_INDEX;
			int bitsPerIndex = 32 - Integers.NumberOfLeadingZeros(maxIndex - 1);

			int data1Len = (numOnes * bitsPerIndex + 7) / 8;
			byte[] data1 = Util.Util.ReadFullLength(stream, data1Len);
			int[] ones = ArrayEncoder.DecodeModQ(data1, numOnes, maxIndex);

			int data2Len = (numNegOnes * bitsPerIndex + 7) / 8;
			byte[] data2 = Util.Util.ReadFullLength(stream, data2Len);
			int[] negOnes = ArrayEncoder.DecodeModQ(data2, numNegOnes, maxIndex);

			return new SparseTernaryPolynomial(N, ones, negOnes);
		}

		/**
		 * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
		 * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
		 *
		 * @param N          number of coefficients
		 * @param numOnes    number of 1's
		 * @param numNegOnes number of -1's
		 */
		public static SparseTernaryPolynomial GenerateRandom(int N, int numOnes, int numNegOnes, SecureRandom random)
		{
			int[] coeffs = Util.Util.GenerateRandomTernary(N, numOnes, numNegOnes, random);
			return new SparseTernaryPolynomial(coeffs);
		}

		public IntegerPolynomial Multiply(IntegerPolynomial poly2)
		{
			int[] b = poly2.coeffs;
			if (b.Length != N)
			{
				throw new InvalidOperationException("Number of coefficients must be the same");
			}

			int[] c = new int[N];
			for (int idx = 0; idx != Ones.Length; idx++)
			{
				int i = Ones[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] += b[j];
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			for (int idx = 0; idx != NegOnes.Length; idx++)
			{
				int i = NegOnes[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] -= b[j];
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			return new IntegerPolynomial(c);
		}

		public IntegerPolynomial Multiply(IntegerPolynomial poly2, int modulus)
		{
			IntegerPolynomial c = Multiply(poly2);
			c.Mod(modulus);
			return c;
		}

		public BigIntPolynomial Multiply(BigIntPolynomial poly2)
		{
			BigInteger[] b = poly2.coeffs;
			if (b.Length != N)
			{
				throw new InvalidOperationException("Number of coefficients must be the same");
			}

			BigInteger[] c = new BigInteger[N];
			for (int i = 0; i < N; i++)
			{
				c[i] = BigInteger.Zero;
			}

			for (int idx = 0; idx != Ones.Length; idx++)
			{
				int i = Ones[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] = c[k].Add(b[j]);
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			for (int idx = 0; idx != NegOnes.Length; idx++)
			{
				int i = NegOnes[idx];
				int j = N - 1 - i;
				for (int k = N - 1; k >= 0; k--)
				{
					c[k] = c[k].Subtract(b[j]);
					j--;
					if (j < 0)
					{
						j = N - 1;
					}
				}
			}

			return new BigIntPolynomial(c);
		}

		public int[] GetOnes()
		{
			return Ones;
		}

		public int[] GetNegOnes()
		{
			return NegOnes;
		}

		/**
		 * Encodes the polynomial to a byte array writing <code>BITS_PER_INDEX</code> bits for each coefficient.
		 *
		 * @return the encoded polynomial
		 */
		public byte[] ToBinary()
		{
			int maxIndex = 1 << BITS_PER_INDEX;
			byte[] bin1 = ArrayEncoder.EncodeModQ(Ones, maxIndex);
			byte[] bin2 = ArrayEncoder.EncodeModQ(NegOnes, maxIndex);

			byte[] bin = new byte[bin1.Length + bin2.Length];
			Array.Copy(bin1, bin, bin1.Length);
			Array.Copy(bin2, 0, bin, bin1.Length, bin2.Length);
			return bin;
		}

		public IntegerPolynomial ToIntegerPolynomial()
		{
			int[] coeffs = new int[N];
			for (int idx = 0; idx != Ones.Length; idx++)
			{
				int i = Ones[idx];
				coeffs[i] = 1;
			}
			for (int idx = 0; idx != NegOnes.Length; idx++)
			{
				int i = NegOnes[idx];
				coeffs[i] = -1;
			}
			return new IntegerPolynomial(coeffs);
		}

		public int Size()
		{
			return N;
		}

		public void Clear()
		{
			for (int i = 0; i < Ones.Length; i++)
			{
				Ones[i] = 0;
			}
			for (int i = 0; i < NegOnes.Length; i++)
			{
				NegOnes[i] = 0;
			}
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + N;
			result = prime * result + NegOnes.GetHashCode();
			result = prime * result + Ones.GetHashCode();
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
			if (GetType() != obj.GetType())
			{
				return false;
			}
			SparseTernaryPolynomial other = (SparseTernaryPolynomial)obj;
			if (N != other.N)
			{
				return false;
			}
			if (!Array.Equals(NegOnes, other.NegOnes))
			{
				return false;
			}
			if (!Array.Equals(Ones, other.Ones))
			{
				return false;
			}
			return true;
		}
	}
}