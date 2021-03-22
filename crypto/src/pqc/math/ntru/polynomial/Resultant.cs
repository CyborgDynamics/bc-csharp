using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{

	/**
	 * Contains a resultant and a polynomial <code>rho</code> such that
	 * <code>res = rho*this + t*(x^n-1) for some integer t</code>.
	 *
	 * @see IntegerPolynomial#resultant()
	 * @see IntegerPolynomial#resultant(int)
	 */
	public class Resultant
	{
		/**
		 * A polynomial such that <code>res = rho*this + t*(x^n-1) for some integer t</code>
		 */
		public BigIntPolynomial Rho;
		/**
		 * Resultant of a polynomial with <code>x^n-1</code>
		 */
		public BigInteger Res;
		public Resultant() { }
		public Resultant(int res) {
			Res = new BigInteger(res.ToString());
		}
		public Resultant(BigIntPolynomial rho, BigInteger res)
		{
			Rho = rho;
			Res = res;
		}
	}
}