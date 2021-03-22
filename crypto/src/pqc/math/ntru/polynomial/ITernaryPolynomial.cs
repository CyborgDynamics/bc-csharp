namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{

	/**
	 * A polynomial whose coefficients are all equal to -1, 0, or 1
	 */
	public interface ITernaryPolynomial : IPolynomial
	{

		/**
		 * Multiplies the polynomial by an <code>IntegerPolynomial</code>, taking the indices mod N
		 */
		//override IntegerPolynomial Multiply(IntegerPolynomial poly2);

		int[] GetOnes();

		int[] GetNegOnes();

		/**
		 * Returns the maximum number of coefficients the polynomial can have
		 */
		int Size();

		void Clear();
	}
}