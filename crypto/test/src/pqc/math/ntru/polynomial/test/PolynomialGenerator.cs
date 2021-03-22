using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.Test
{
	public class PolynomialGenerator
	{
		/**
		 * Creates a random polynomial with <code>N</code> coefficients
		 * between <code>0</code> and <code>q-1</code>.
		 *
		 * @param N length of the polynomial
		 * @param q coefficients will all be below this number
		 * @return a random polynomial
		 */
		public static IntegerPolynomial GenerateRandom(int N, int q)
		{
			SecureRandom rng = new SecureRandom();
			int[] coeffs = new int[N];
			for (int i = 0; i < N; i++)
			{
				coeffs[i] = rng.NextInt(q);
			}
			return new IntegerPolynomial(coeffs);
		}
	}
}