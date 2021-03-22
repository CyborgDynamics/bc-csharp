using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pqc.Math.Ntru.Util;
namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{

	/**
	 * A <code>TernaryPolynomial</code> with a "high" number of nonzero coefficients.
	 */
	public class DenseTernaryPolynomial : IntegerPolynomial, ITernaryPolynomial
	{

		/**
		 * Constructs a new <code>DenseTernaryPolynomial</code> with <code>N</code> coefficients.
		 *
		 * @param N the number of coefficients
		 */
		DenseTernaryPolynomial(int N) : base(N)
		{
			checkTernarity();
		}

		/**
		 * Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		 * independent of each other.
		 *
		 * @param intPoly the original polynomial
		 */
		public DenseTernaryPolynomial(IntegerPolynomial intPoly) : this(intPoly.coeffs)
		{
		}

		/**
		 * Constructs a new <code>DenseTernaryPolynomial</code> with a given set of coefficients.
		 *
		 * @param coeffs the coefficients
		 */
		public DenseTernaryPolynomial(int[] coeffs) : base(coeffs)
		{
			checkTernarity();
		}

		private void checkTernarity()
		{
			for (int i = 0; i != coeffs.Length; i++)
			{
				int c = coeffs[i];
				if (c < -1 || c > 1)
				{
					throw new InvalidOperationException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
				}
			}
		}

		/**
		 * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
		 * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
		 *
		 * @param N          number of coefficients
		 * @param numOnes    number of 1's
		 * @param numNegOnes number of -1's
		 */
		public static DenseTernaryPolynomial GenerateRandom(int N, int numOnes, int numNegOnes, SecureRandom random)
		{
			int[] coeffs = Util.Util.GenerateRandomTernary(N, numOnes, numNegOnes, random);
			return new DenseTernaryPolynomial(coeffs);
		}

		/**
		 * Generates a polynomial with coefficients randomly selected from <code>{-1, 0, 1}</code>.
		 *
		 * @param N number of coefficients
		 */
		public static DenseTernaryPolynomial GenerateRandom(int N, SecureRandom random)
		{
			DenseTernaryPolynomial poly = new DenseTernaryPolynomial(N);
			for (int i = 0; i < N; i++)
			{
				poly.coeffs[i] = random.NextInt(3) - 1;
			}
			return poly;
		}

		public new IntegerPolynomial Multiply(IntegerPolynomial poly2, int modulus)
		{
			// even on 32-bit systems, LongPolynomial5 multiplies faster than IntegerPolynomial
			if (modulus == 2048)
			{
				IntegerPolynomial poly2Pos = (IntegerPolynomial)poly2.Clone();
				poly2Pos.ModPositive(2048);
				LongPolynomial5 poly5 = new LongPolynomial5(poly2Pos);
				return poly5.Multiply(this).ToIntegerPolynomial();
			}
			else
			{
				return base.Multiply(poly2, modulus);
			}
		}

		public int[] GetOnes()
		{
			int N = coeffs.Length;
			int[] ones = new int[N];
			int onesIdx = 0;
			for (int i = 0; i < N; i++)
			{
				int c = coeffs[i];
				if (c == 1)
				{
					ones[onesIdx++] = i;
				}
			}
			int[] toRet = new int[onesIdx];
			Array.Copy(ones, toRet, onesIdx);
			return toRet;
		}

		public int[] GetNegOnes()
		{
			int N = coeffs.Length;
			int[] negOnes = new int[N];
			int negOnesIdx = 0;
			for (int i = 0; i < N; i++)
			{
				int c = coeffs[i];
				if (c == -1)
				{
					negOnes[negOnesIdx++] = i;
				}
			}
			int[] toRet = new int[negOnesIdx];
			Array.Copy(negOnes, toRet, negOnesIdx);
			return toRet;

		}

		public int Size()
		{
			return coeffs.Length;
		}
	}

}