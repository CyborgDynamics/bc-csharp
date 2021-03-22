using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Euclid
{
	/**
	 * Extended Euclidean Algorithm in <code>BigInteger</code>s
	 */
	public class BigIntEuclidean
	{
		public BigInteger x, y, gcd;

		private BigIntEuclidean()
		{
		}

		/**
		 * Runs the EEA on two <code>BigInteger</code>s<br>
		 * Implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm">Wikipedia</a>.
		 *
		 * @param a
		 * @param b
		 * @return a <code>BigIntEuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
		 */
		public static BigIntEuclidean Calculate(BigInteger a, BigInteger b)
		{
			BigInteger x = BigInteger.Zero;
			BigInteger lastx = BigInteger.One;
			BigInteger y = BigInteger.One;
			BigInteger lasty = BigInteger.Zero;
			while (!b.Equals(BigInteger.Zero))
			{
				BigInteger[] quotientAndRemainder = a.DivideAndRemainder(b);
				BigInteger quotient = quotientAndRemainder[0];

				BigInteger temp = a;
				a = b;
				b = quotientAndRemainder[1];

				temp = x;
				x = lastx.Subtract(quotient.Multiply(x));
				lastx = temp;

				temp = y;
				y = lasty.Subtract(quotient.Multiply(y));
				lasty = temp;
			}

			BigIntEuclidean result = new BigIntEuclidean();
			result.x = lastx;
			result.y = lasty;
			result.gcd = a;
			return result;
		}
	}
}