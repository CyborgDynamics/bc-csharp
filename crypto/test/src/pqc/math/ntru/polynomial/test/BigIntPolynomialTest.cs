using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.Test
{
public class BigIntPolynomialTest : SimpleTest
{
		public override string Name => "BigIntPolynomial";

        [Test]
		public override void PerformTest()
		{
            testMult();
		}

		public void testMult()
    {
        BigIntPolynomial a = new BigIntPolynomial(new IntegerPolynomial(new int[]{4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5}));
        BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[]{-6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1}));
        BigIntPolynomial c = a.Multiply(b);
        BigInteger[] expectedCoeffs = new BigIntPolynomial(new IntegerPolynomial(new int[]{2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34})).GetCoeffs();
        BigInteger[] cCoeffs = c.GetCoeffs();

        Assert.AreEqual(expectedCoeffs.Length, cCoeffs.Length);
        for (int i = 0; i != cCoeffs.Length; i++)
        {
            Assert.AreEqual(expectedCoeffs[i], cCoeffs[i]);
        }
    }
}
}