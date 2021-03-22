using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.Test
{


	public class BigDecimalPolynomialTest : SimpleTest
	{
		public override string Name => "BigDecimalPolynomial";

		[Test]
		public override void PerformTest()
		{
			testMult();
		}

		public void testMult()
		{
			BigDecimalPolynomial a = new BigDecimalPolynomial(new BigIntPolynomial(new IntegerPolynomial(new int[] { 4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5 })));
			BigDecimalPolynomial b = new BigDecimalPolynomial(new BigIntPolynomial(new IntegerPolynomial(new int[] { -6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1 })));
			BigDecimalPolynomial c = a.Multiply(b);
			decimal[] expectedCoeffs = new BigDecimalPolynomial(new BigIntPolynomial(new IntegerPolynomial(new int[] { 2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34 }))).getCoeffs();

			decimal[] cCoeffs = c.getCoeffs();

			Assert.AreEqual(expectedCoeffs.Length, cCoeffs.Length);
			for (int i = 0; i != cCoeffs.Length; i++)
			{
				Assert.AreEqual(expectedCoeffs[i], cCoeffs[i]);
			}

			// multiply a polynomial by its inverse modulo 2048 and check that the result is 1
			SecureRandom random = new SecureRandom();
			IntegerPolynomial d, dInv;
			do
			{
				d = DenseTernaryPolynomial.GenerateRandom(1001, 333, 334, random);
				dInv = d.InvertFq(2048);
			}
			while (dInv == null);

			d.Mod(2048);
			BigDecimalPolynomial e = new BigDecimalPolynomial(new BigIntPolynomial(d));
			BigIntPolynomial f = new BigIntPolynomial(dInv);
			IntegerPolynomial g = new IntegerPolynomial(e.Multiply(f).round());
			g.ModPositive(2048);
			Assert.True(g.EqualsOne());
		}
	}
}