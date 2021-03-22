using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Pqc.Math.Ntru.Polynomial;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.Bouncycastle.Pqc.Math.Ntru.Polynomial.Test
{

	public class SparseTernaryPolynomialTest : SimpleTest
	{
		public override string Name => "SparseTernaryPolynomial";

		/**
		 * tests mult(IntegerPolynomial) and mult(BigIntPolynomial)
		 */
		public void testMult()
		{
			SecureRandom random = new SecureRandom();
			SparseTernaryPolynomial p1 = SparseTernaryPolynomial.GenerateRandom(1000, 500, 500, random);
			IntegerPolynomial p2 = DenseTernaryPolynomial.GenerateRandom(1000, random);

			IntegerPolynomial prod1 = p1.Multiply(p2);
			IntegerPolynomial prod2 = p1.Multiply(p2);
			Assert.AreEqual(prod1.coeffs, prod2.coeffs);

			BigIntPolynomial p3 = new BigIntPolynomial(p2);
			BigIntPolynomial prod3 = p1.Multiply(p3);

			Assert.AreEqual((new BigIntPolynomial(prod1)).coeffs, prod3.coeffs);
		}

		public void testFromToBinary()
		{
			SecureRandom random = new SecureRandom();
			SparseTernaryPolynomial poly1 = SparseTernaryPolynomial.GenerateRandom(1000, 100, 101, random);
			MemoryStream poly1Stream = new MemoryStream(poly1.ToBinary());
			SparseTernaryPolynomial poly2 = SparseTernaryPolynomial.FromBinary(poly1Stream, 1000, 100, 101);
			Assert.AreEqual(poly1.GetOnes(), poly2.GetOnes());
			Assert.AreEqual(poly1.GetNegOnes(), poly2.GetNegOnes());
			Assert.AreEqual(poly1.ToIntegerPolynomial().coeffs, poly2.ToIntegerPolynomial().coeffs);
		}

		[Test]
		public override void PerformTest()
		{
			testMult();
			testFromToBinary();
		}
	}
}