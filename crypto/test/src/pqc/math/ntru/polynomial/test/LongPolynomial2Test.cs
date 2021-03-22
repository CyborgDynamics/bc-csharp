using Org.BouncyCastle.Utilities.Test;
using NUnit.Framework;
using System;
using System.Linq;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.Test
{
	public class LongPolynomial2Test : SimpleTest
	{
		public override string Name => "LongPolynomial2";
	
		public void testMult()
		{
			IntegerPolynomial i1 = new IntegerPolynomial(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 });
			IntegerPolynomial i2 = new IntegerPolynomial(new int[] { 1729, 1924, 806, 179, 1530, 1381, 1695, 60 });
			LongPolynomial2 a = new LongPolynomial2(i1);
			LongPolynomial2 b = new LongPolynomial2(i2);
			IntegerPolynomial c1 = i1.Multiply(i2, 2048);
			IntegerPolynomial c2 = a.Multiply(b).ToIntegerPolynomial();
			Assert.True(c1.coeffs.SequenceEqual(c2.coeffs));

			SecureRandom rng = new SecureRandom();
			for (int i = 0; i < 10; i++)
			{
				int N = 2 + rng.NextInt(2000);
				i1 = PolynomialGenerator.GenerateRandom(N, 2048);
				i2 = PolynomialGenerator.GenerateRandom(N, 2048);
				a = new LongPolynomial2(i1);
				b = new LongPolynomial2(i2);
				c1 = i1.Multiply(i2);
				c1.ModPositive(2048);
				c2 = a.Multiply(b).ToIntegerPolynomial();
				Assert.True(c1.coeffs.SequenceEqual(c2.coeffs));
			}
		}

		public void testSubAnd()
		{
			IntegerPolynomial i1 = new IntegerPolynomial(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 });
			IntegerPolynomial i2 = new IntegerPolynomial(new int[] { 1729, 1924, 806, 179, 1530, 1381, 1695, 60 });
			LongPolynomial2 a = new LongPolynomial2(i1);
			LongPolynomial2 b = new LongPolynomial2(i2);
			a.SubAnd(b, 2047);
			i1.Sub(i2);
			i1.ModPositive(2048);
			Assert.True(a.ToIntegerPolynomial().coeffs.SequenceEqual(i1.coeffs));
		}

		public void testMult2And()
		{
			IntegerPolynomial i1 = new IntegerPolynomial(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 });
			LongPolynomial2 i2 = new LongPolynomial2(i1);
			i2.mult2And(2047);
			i1.Multiply(2);
			i1.ModPositive(2048);
			Assert.True(i1.coeffs.SequenceEqual(i2.ToIntegerPolynomial().coeffs));
		}

		public override void PerformTest()
		{
			testMult();
			testSubAnd();
			testMult2And();
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}