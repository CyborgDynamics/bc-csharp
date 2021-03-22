using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.Test
{
	public class LongPolynomial5Test : SimpleTest
	{
		public override string Name => "LongPolynomial5Test";

		public void testMult()
		{
			testMult(new int[] { 2 }, new int[] { -1 });
			testMult(new int[] { 2, 0 }, new int[] { -1, 0 });
			testMult(new int[] { 2, 0, 3 }, new int[] { -1, 0, 1 });
			testMult(new int[] { 2, 0, 3, 1 }, new int[] { -1, 0, 1, 1 });
			testMult(new int[] { 2, 0, 3, 1, 2 }, new int[] { -1, 0, 1, 1, 0 });
			testMult(new int[] { 2, 0, 3, 1, 1, 5 }, new int[] { 1, -1, 1, 1, 0, 1 });
			testMult(new int[] { 2, 0, 3, 1, 1, 5, 1, 4 }, new int[] { 1, 0, 1, 1, -1, 1, 0, -1 });
			testMult(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 }, new int[] { 1, 0, 1, 1, -1, 1, 0, -1 });

			// test random polynomials
			SecureRandom rng = new SecureRandom();
			for (int i = 0; i < 10; i++)
			{
				int[] coeffs1 = new int[rng.NextInt(2000) + 1];
				int[] coeffs2 = DenseTernaryPolynomial.GenerateRandom(coeffs1.Length, rng).coeffs;
				testMult(coeffs1, coeffs2);
			}
		}

		private void testMult(int[] coeffs1, int[] coeffs2)
		{
			IntegerPolynomial i1 = new IntegerPolynomial(coeffs1);
			IntegerPolynomial i2 = new IntegerPolynomial(coeffs2);

			LongPolynomial5 a = new LongPolynomial5(i1);
			DenseTernaryPolynomial b = new DenseTernaryPolynomial(i2);
			IntegerPolynomial c1 = i1.Multiply(i2, 2048);
			IntegerPolynomial c2 = a.Multiply(b).ToIntegerPolynomial();
			assertEqualsMod(c1.coeffs, c2.coeffs, 2048);
		}

		private void assertEqualsMod(int[] arr1, int[] arr2, int m)
		{
			Assert.AreEqual(arr1.Length, arr2.Length);
			for (int i = 0; i < arr1.Length; i++)
			{
				Assert.AreEqual((arr1[i] + m) % m, (arr2[i] + m) % m);
			}
		}

		public void testToIntegerPolynomial()
		{
			int[] coeffs = new int[] { 2, 0, 3, 1, 1, 5, 1, 4 };
			LongPolynomial5 p = new LongPolynomial5(new IntegerPolynomial(coeffs));
			Assert.True(coeffs.SequenceEqual(p.ToIntegerPolynomial().coeffs));
		}

		[Test]
		public override void PerformTest()
		{
			testMult();
			testToIntegerPolynomial();
		}
	}
}