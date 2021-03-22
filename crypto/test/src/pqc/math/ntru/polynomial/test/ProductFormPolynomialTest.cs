using NUnit.Framework;

using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.Test
{

	public class ProductFormPolynomialTest : SimpleTest
	{
		private NTRUEncryptionKeyGenerationParameters parameters;
		private int N;
		private int df1;
		private int df2;
		private int df3;
		private int q;

		public override string Name => "ProductFormPolynomial";

		[Test]
		public override void PerformTest()
		{
			setUp();
			testMult();
			testFromToBinary();
		}

		public void setUp()
		{
			parameters = NTRUEncryptionKeyGenerationParameters.APR2011_439_FAST;
			N = parameters.N;
			df1 = parameters.df1;
			df2 = parameters.df2;
			df3 = parameters.df3;
			q = parameters.q;
		}

		public void testFromToBinary()
		{
			ProductFormPolynomial p1 = ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3 - 1, new SecureRandom());
			byte[] bin1 = p1.ToBinary();
			ProductFormPolynomial p2 = ProductFormPolynomial.FromBinary(bin1, N, df1, df2, df3, df3 - 1);
			Assert.AreEqual(p1.ToIntegerPolynomial().coeffs, p2.ToIntegerPolynomial().coeffs);
		}

		public void testMult()
		{
			ProductFormPolynomial p1 = ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3 - 1, new SecureRandom());
			IntegerPolynomial p2 = PolynomialGenerator.GenerateRandom(N, q);
			IntegerPolynomial p3 = p1.Multiply(p2);
			IntegerPolynomial p4 = p1.ToIntegerPolynomial().Multiply(p2);
			Assert.AreEqual(p3.ToIntegerPolynomial().coeffs, p4.ToIntegerPolynomial().coeffs);
		}
	}
}