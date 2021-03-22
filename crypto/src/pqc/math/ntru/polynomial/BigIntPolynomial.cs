using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{
    public class BigIntPolynomial
    {
        private static double LOG_10_2 = System.Math.Log10(2);

        public BigInteger[] coeffs;

        /**
         * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
         *
         * @param N the number of coefficients
         */
        public BigIntPolynomial(int N)
        {
            coeffs = new BigInteger[N];
            for (int i = 0; i < N; i++)
            {
                coeffs[i] = BigInteger.ValueOf(0);
            }
        }

        /**
         * Constructs a new polynomial with a given set of coefficients.
         *
         * @param coeffs the coefficients
         */
        public BigIntPolynomial(BigInteger[] coeffs)
        {
            this.coeffs = coeffs;
        }

        /**
         * Constructs a <code>BigIntPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
         * independent of each other.
         *
         * @param p the original polynomial
         */
        public BigIntPolynomial(IntegerPolynomial p)
        {
            coeffs = new BigInteger[p.coeffs.Length];
            for (int i = 0; i < coeffs.Length; i++)
            {
                coeffs[i] = BigInteger.ValueOf(p.coeffs[i]);
            }
        }

        /**
         * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
         * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
         *
         * @param N          number of coefficients
         * @param numOnes    number of 1's
         * @param numNegOnes number of -1's
         * @return a random polynomial.
         */
        static BigIntPolynomial GenerateRandomSmall(int N, int numOnes, int numNegOnes)
        {
            List<BigInteger> coeffs = new List<BigInteger>();
            for (int i = 0; i < numOnes; i++)
            {
                coeffs.Add(BigInteger.ValueOf(1));
            }
            for (int i = 0; i < numNegOnes; i++)
            {
                coeffs.Add(BigInteger.ValueOf(-1));
            }
            while (coeffs.Count < N)
            {
                coeffs.Add(BigInteger.ValueOf(0));
            }

            Shuffle(coeffs, CryptoServicesRegistrar.GetSecureRandom());

            BigIntPolynomial poly = new BigIntPolynomial(N);
            for (int i = 0; i < coeffs.Count; i++)
            {
                poly.coeffs[i] = (BigInteger)coeffs[i];
            }
            return poly;
        }

		private static void Shuffle(List<BigInteger> coeffs, object p)
		{
			throw new NotImplementedException();
		}

		/**
         * Multiplies the polynomial by another, taking the indices mod N. Does not
         * change this polynomial but returns the result as a new polynomial.<br>
         * Both polynomials must have the same number of coefficients.
         *
         * @param poly2 the polynomial to multiply by
         * @return a new polynomial
         */
		public BigIntPolynomial Multiply(BigIntPolynomial poly2)
        {
            int N = coeffs.Length;
            if (poly2.coeffs.Length != N)
            {
                throw new InvalidOperationException("MULT: Number of coefficients must be the same");
            }

            BigIntPolynomial c = MultiplyRecursive(poly2);

            if (c.coeffs.Length > N)
            {
                for (int k = N; k < c.coeffs.Length; k++)
                {
                    c.coeffs[k - N] = c.coeffs[k - N].Add(c.coeffs[k]);
                }
				
				// Shortening the Array
				BigInteger[] temp = new BigInteger[N];
                Array.Copy(c.coeffs, temp, N);
				c.coeffs = temp;
                
            }
            return c;
        }

        /**
         * Karazuba multiplication
         */
        private BigIntPolynomial MultiplyRecursive(BigIntPolynomial poly2)
        {
            BigInteger[] a = coeffs;
            BigInteger[] b = poly2.coeffs;

            int n = poly2.coeffs.Length;
            if (n <= 1)
            {
                BigInteger[] c = new BigInteger[coeffs.Length];
				Array.Copy(coeffs, c, coeffs.Length);
                for (int i = 0; i < coeffs.Length; i++)
                {
                    c[i] = c[i].Multiply(poly2.coeffs[0]);
                }
                return new BigIntPolynomial(c);
            }
            else
            {
                int n1 = n / 2;

                // TODO: Double Check Conversion (Don't worry too much, it'll explode if wrong)... It Exploded
                BigInteger[] a1temp = new BigInteger[n1];
                BigInteger[] a2temp = new BigInteger[n - n1];
                BigInteger[] b1temp = new BigInteger[n1];
                BigInteger[] b2temp = new BigInteger[n - n1];

                Array.Copy(a, a1temp, n1);
                Array.Copy(a, n1, a2temp, 0, n-n1);
                Array.Copy(b, b1temp, n1);
                Array.Copy(b, n1, b2temp, 0, n-n1);

                BigIntPolynomial a1 = new BigIntPolynomial(a1temp);
                BigIntPolynomial a2 = new BigIntPolynomial(a2temp);
                BigIntPolynomial b1 = new BigIntPolynomial(b1temp);
                BigIntPolynomial b2 = new BigIntPolynomial(b2temp);

                BigIntPolynomial A = (BigIntPolynomial)a1.Clone();
                A.Add(a2);
                BigIntPolynomial B = (BigIntPolynomial)b1.Clone();
                B.Add(b2);

                BigIntPolynomial c1 = a1.MultiplyRecursive(b1);
                BigIntPolynomial c2 = a2.MultiplyRecursive(b2);
                BigIntPolynomial c3 = A.MultiplyRecursive(B);
                c3.Sub(c1);
                c3.Sub(c2);

                BigIntPolynomial c = new BigIntPolynomial(2 * n - 1);
                for (int i = 0; i < c1.coeffs.Length; i++)
                {
                    c.coeffs[i] = c1.coeffs[i];
                }
                for (int i = 0; i < c3.coeffs.Length; i++)
                {
                    c.coeffs[n1 + i] = c.coeffs[n1 + i].Add(c3.coeffs[i]);
                }
                for (int i = 0; i < c2.coeffs.Length; i++)
                {
                    c.coeffs[2 * n1 + i] = c.coeffs[2 * n1 + i].Add(c2.coeffs[i]);
                }
                return c;
            }
        }

        /**
         * Adds another polynomial which can have a different number of coefficients,
         * and takes the coefficient values mod <code>modulus</code>.
         *
         * @param b another polynomial
         */
        void Add(BigIntPolynomial b, BigInteger modulus)
        {
            Add(b);
            Mod(modulus);
        }

        /**
         * Adds another polynomial which can have a different number of coefficients.
         *
         * @param b another polynomial
         */
        public void Add(BigIntPolynomial b)
        {
            if (b.coeffs.Length > coeffs.Length)
            {
                int N = coeffs.Length;
				BigInteger[] temp = new BigInteger[b.coeffs.Length];
                Array.Copy(coeffs, temp, coeffs.Length);
				coeffs = temp;
                for (int i = N; i < coeffs.Length; i++)
                {
                    coeffs[i] = BigInteger.ValueOf(0);
                }
            }
            for (int i = 0; i < b.coeffs.Length; i++)
            {
				// b.coeffs[i] and coeffs[i] should never be null. If they are, somethings wrong.
				coeffs[i] = coeffs[i].Add(b.coeffs[i]);
            }
        }

        /**
         * Subtracts another polynomial which can have a different number of coefficients.
         *
         * @param b another polynomial
         */
        public void Sub(BigIntPolynomial b)
        {
            if (b.coeffs.Length > coeffs.Length)
            {
                int N = coeffs.Length;
                Array.Copy(coeffs, coeffs, b.coeffs.Length);
                for (int i = N; i < coeffs.Length; i++)
                {
                    coeffs[i] = BigInteger.ValueOf(0);
                }
            }
            for (int i = 0; i < b.coeffs.Length; i++)
            {
                coeffs[i] = coeffs[i].Subtract(b.coeffs[i]);
            }
        }

        /**
         * Multiplies each coefficient by a <code>BigInteger</code>. Does not return a new polynomial but modifies this polynomial.
         *
         * @param factor
         */
        public void Multiply(BigInteger factor)
        {
            for (int i = 0; i < coeffs.Length; i++)
            {
                coeffs[i] = coeffs[i].Multiply(factor);
            }
        }

        /**
         * Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
         *
         * @param factor
         */
        void Multiply(int factor)
        {
			Multiply(BigInteger.ValueOf(factor));
        }

        /**
         * Divides each coefficient by a <code>BigInteger</code> and rounds the result to the nearest whole number.<br>
         * Does not return a new polynomial but modifies this polynomial.
         *
         * @param divisor the number to divide by
         */
        public void Divide(BigInteger divisor)
        {
            BigInteger d = divisor.Add(BigInteger.ValueOf(1)).Divide(BigInteger.ValueOf(2));
            for (int i = 0; i < coeffs.Length; i++)
            {
                coeffs[i] = coeffs[i].CompareTo(BigInteger.ValueOf(0)) > 0 ? coeffs[i].Add(d) : coeffs[i].Add(d.Negate());
                coeffs[i] = coeffs[i].Divide(divisor);
            }
        }

        /**
         * Divides each coefficient by a <code>BigDecimal</code> and rounds the result to <code>decimalPlaces</code> places.
         *
         * @param divisor       the number to divide by
         * @param decimalPlaces the number of fractional digits to round the result to
         * @return a new <code>BigDecimalPolynomial</code>
         */
        public BigDecimalPolynomial Divide(decimal divisor, int decimalPlaces)
        {
            BigInteger max = MaxCoeffAbs();
            int coeffLength = (int)(max.BitLength * LOG_10_2) + 1;
			// factor = 1/divisor
			decimal factor = decimal.Round(decimal.Divide(Constants.BIGDEC_ONE, divisor), coeffLength + decimalPlaces + 1, MidpointRounding.AwayFromZero); //decimal.ROUND_HALF_EVEN);

            // multiply each coefficient by factor
            BigDecimalPolynomial p = new BigDecimalPolynomial(coeffs.Length);
            for (int i = 0; i < coeffs.Length; i++)
            // multiply, then truncate after decimalPlaces so subsequent operations aren't slowed down
            {
				p.coeffs[i] = decimal.Round(decimal.Multiply(new decimal(coeffs[i].IntValue), factor), decimalPlaces, MidpointRounding.AwayFromZero);// BigDecimal.ROUND_HALF_EVEN);
            }

            return p;
        }

        /**
         * Returns the base10 length of the largest coefficient.
         *
         * @return length of the longest coefficient
         */
        public int GetMaxCoeffLength()
        {
            return (int)(MaxCoeffAbs().BitLength * LOG_10_2) + 1;
        }

        private BigInteger MaxCoeffAbs()
        {
            BigInteger max = coeffs[0].Abs();
            for (int i = 1; i < coeffs.Length; i++)
            {
                BigInteger coeff = coeffs[i].Abs();
                if (coeff.CompareTo(max) > 0)
                {
                    max = coeff;
                }
            }
            return max;
        }

        /**
         * Takes each coefficient modulo a number.
         *
         * @param modulus
         */
        public void Mod(BigInteger modulus)
        {
            for (int i = 0; i < coeffs.Length; i++)
            {
                coeffs[i] = coeffs[i].Mod(modulus);
            }
        }

        /**
         * Returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
         *
         * @return the sum of all coefficients
         */
        BigInteger SumCoeffs()
        {
            BigInteger sum = BigInteger.ValueOf(0);
            for (int i = 0; i < coeffs.Length; i++)
            {
                sum = sum.Add(coeffs[i]);
            }
            return sum;
        }

        /**
         * Makes a copy of the polynomial that is independent of the original.
         */
        public object Clone()
        {
            return new BigIntPolynomial((BigInteger[])coeffs.Clone());
        }

        public override int GetHashCode()
        {
            const int prime = 31;
            int result = 1;
            result = prime * result + coeffs.GetHashCode();
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
            BigIntPolynomial other = (BigIntPolynomial)obj;
            if (!Array.Equals(coeffs, other.coeffs))
            {
                return false;
            }
            return true;
        }

        public BigInteger[] GetCoeffs()
        {
            return (BigInteger[])coeffs.Clone();
        }
    }
}