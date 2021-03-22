using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{
	/**
	 * A polynomial with {@link BigDecimal} coefficients.
	 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
	 * not but return the result as a new polynomial.
	 */

	public class BigDecimalPolynomial
	{
		private static decimal ZERO = decimal.Zero;
		private static decimal ONE_HALF = decimal.Parse("0.5");

		public decimal[] coeffs;

		/**
		 * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
		 *
		 * @param N the number of coefficients
		 */
		public BigDecimalPolynomial(int N)
		{
			coeffs = new decimal[N];
			for (int i = 0; i < N; i++)
			{
				coeffs[i] = ZERO;
			}
		}

		/**
		 * Constructs a new polynomial with a given set of coefficients.
		 *
		 * @param coeffs the coefficients
		 */
		BigDecimalPolynomial(decimal[] coeffs)
		{
			this.coeffs = coeffs;
		}

		/**
		 * Constructs a <code>BigDecimalPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are independent of each other.
		 *
		 * @param p the original polynomial
		 */
		public BigDecimalPolynomial(BigIntPolynomial p)
		{
			int N = p.coeffs.Length;
			coeffs = new decimal[N];
			for (int i = 0; i < N; i++)
			{
				coeffs[i] = new decimal(p.coeffs[i].IntValue);
			}
		}

		/**
		 * Divides all coefficients by 2.
		 */
		public void Halve()
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] = decimal.Multiply(coeffs[i], ONE_HALF);
			}
		}

		/**
		 * Multiplies the polynomial by another. Does not change this polynomial
		 * but returns the result as a new polynomial.
		 *
		 * @param poly2 the polynomial to multiply by
		 * @return a new polynomial
		 */
		public BigDecimalPolynomial Multiply(BigIntPolynomial poly2)
		{
			return Multiply(new BigDecimalPolynomial(poly2));
		}

		/**
		 * Multiplies the polynomial by another, taking the indices mod N. Does not
		 * change this polynomial but returns the result as a new polynomial.
		 *
		 * @param poly2 the polynomial to multiply by
		 * @return a new polynomial
		 */
		public BigDecimalPolynomial Multiply(BigDecimalPolynomial poly2)
		{
			int N = coeffs.Length;
			if (poly2.coeffs.Length != N)
			{
				throw new InvalidOperationException("Number of coefficients must be the same");
			}

			BigDecimalPolynomial c = multRecursive(poly2);

			if (c.coeffs.Length > N)
			{
				for (int k = N; k < c.coeffs.Length; k++)
				{
					c.coeffs[k - N] = decimal.Add(c.coeffs[k - N], c.coeffs[k]);
				}
				c.coeffs = copyOf(c.coeffs, N);
			}
			return c;
		}

		/**
		 * Karazuba multiplication
		 */
		private BigDecimalPolynomial multRecursive(BigDecimalPolynomial poly2)
		{
			decimal[] a = coeffs;
			decimal[] b = poly2.coeffs;

			int n = poly2.coeffs.Length;
			if (n <= 1)
			{
				decimal[] c = (decimal[])coeffs.Clone();
				for (int i = 0; i < coeffs.Length; i++)
				{
					c[i] = decimal.Multiply(c[i], poly2.coeffs[0]);
				}
				return new BigDecimalPolynomial(c);
			}
			else
			{
				int n1 = n / 2;

				BigDecimalPolynomial a1 = new BigDecimalPolynomial(copyOf(a, n1));
				BigDecimalPolynomial a2 = new BigDecimalPolynomial(copyOfRange(a, n1, n));
				BigDecimalPolynomial b1 = new BigDecimalPolynomial(copyOf(b, n1));
				BigDecimalPolynomial b2 = new BigDecimalPolynomial(copyOfRange(b, n1, n));

				BigDecimalPolynomial A = (BigDecimalPolynomial)a1.Clone();
				A.Add(a2);
				BigDecimalPolynomial B = (BigDecimalPolynomial)b1.Clone();
				B.Add(b2);

				BigDecimalPolynomial c1 = a1.multRecursive(b1);
				BigDecimalPolynomial c2 = a2.multRecursive(b2);
				BigDecimalPolynomial c3 = A.multRecursive(B);
				c3.Sub(c1);
				c3.Sub(c2);

				BigDecimalPolynomial c = new BigDecimalPolynomial(2 * n - 1);
				for (int i = 0; i < c1.coeffs.Length; i++)
				{
					c.coeffs[i] = c1.coeffs[i];
				}
				for (int i = 0; i < c3.coeffs.Length; i++)
				{
					c.coeffs[n1 + i] = decimal.Add(c.coeffs[n1 + i],(c3.coeffs[i]));
				}
				for (int i = 0; i < c2.coeffs.Length; i++)
				{
					c.coeffs[2 * n1 + i] = decimal.Add(c.coeffs[2 * n1 + i], (c2.coeffs[i]));
				}
				return c;
			}
		}

		/**
		 * Adds another polynomial which can have a different number of coefficients.
		 *
		 * @param b another polynomial
		 */
		public void Add(BigDecimalPolynomial b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				int N = coeffs.Length;
				coeffs = copyOf(coeffs, b.coeffs.Length);
				for (int i = N; i < coeffs.Length; i++)
				{
					coeffs[i] = ZERO;
				}
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] = decimal.Add(coeffs[i], b.coeffs[i]);
			}
		}

		/**
		 * Subtracts another polynomial which can have a different number of coefficients.
		 *
		 * @param b
		 */
		void Sub(BigDecimalPolynomial b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				int N = coeffs.Length;
				coeffs = copyOf(coeffs, b.coeffs.Length);
				for (int i = N; i < coeffs.Length; i++)
				{
					coeffs[i] = ZERO;
				}
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] = decimal.Subtract(coeffs[i], b.coeffs[i]);
			}
		}

		/**
		 * Rounds all coefficients to the nearest integer.
		 *
		 * @return a new polynomial with <code>BigInteger</code> coefficients
		 */
		public BigIntPolynomial round()
		{
			int N = coeffs.Length;
			BigIntPolynomial p = new BigIntPolynomial(N);
			for (int i = 0; i < N; i++)
			{
				p.coeffs[i] = new BigInteger(decimal.Round(coeffs[i], 0, MidpointRounding.AwayFromZero).ToString()); //BigDecimal.ROUND_HALF_EVEN).toBigInteger();
			}
			return p;
		}

		/**
		 * Makes a copy of the polynomial that is independent of the original.
		 */
		public object Clone()
		{
			return new BigDecimalPolynomial((decimal[])coeffs.Clone());
		}

		private decimal[] copyOf(decimal[] a, int length)
		{
			decimal[] tmp = new decimal[length];

			Array.Copy(a, 0, tmp, 0, a.Length < length ? a.Length : length);

			return tmp;
		}

		private decimal[] copyOfRange(decimal[] a, int from, int to)
		{
			int newLength = to - from;
			decimal[] tmp = new decimal[to - from];

			Array.Copy(a, from, tmp, 0, (a.Length - from) < newLength ? (a.Length - from) : newLength);

			return tmp;
		}

		public decimal[] getCoeffs()
		{
			decimal[] tmp = new decimal[coeffs.Length];

			Array.Copy(coeffs, 0, tmp, 0, coeffs.Length);

			return tmp;
		}

	}
}