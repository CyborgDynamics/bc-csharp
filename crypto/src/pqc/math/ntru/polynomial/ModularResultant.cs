using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Math.Ntru.Euclid;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{


	/**
	 * A resultant modulo a <code>BigInteger</code>
	 */
	public class ModularResultant : Resultant
	{
		BigInteger modulus;
		public ModularResultant() { }

		public ModularResultant(int modulus)
		{
			this.modulus = new BigInteger(modulus.ToString());
		}
		public ModularResultant(BigIntPolynomial rho, BigInteger res, BigInteger modulus) : base(rho, res)
		{
			this.modulus = modulus;
		}

		/**
		 * Calculates a <code>rho</code> modulo <code>m1*m2</code> from
		 * two resultants whose <code>rho</code>s are modulo <code>m1</code> and <code>m2</code>.<br/>
		 * </code>res</code> is set to <code>null</code>.
		 *
		 * @param modRes1
		 * @param modRes2
		 * @return <code>rho</code> modulo <code>modRes1.modulus * modRes2.modulus</code>, and <code>null</code> for </code>res</code>.
		 */
		public static ModularResultant CombineRho(ModularResultant modRes1, ModularResultant modRes2)
		{
			BigInteger mod1 = modRes1.modulus;
			BigInteger mod2 = modRes2.modulus;
			BigInteger prod = mod1.Multiply(mod2);
			BigIntEuclidean er = BigIntEuclidean.Calculate(mod2, mod1);

			BigIntPolynomial rho1 = (BigIntPolynomial)modRes1.Rho.Clone();
			rho1.Multiply(er.x.Multiply(mod2));

			BigIntPolynomial rho2 = (BigIntPolynomial)modRes2.Rho.Clone();
			rho2.Multiply(er.y.Multiply(mod1));

			rho1.Add(rho2);
			rho1.Mod(prod);

			return new ModularResultant(rho1, null, prod);
		}
	}
}