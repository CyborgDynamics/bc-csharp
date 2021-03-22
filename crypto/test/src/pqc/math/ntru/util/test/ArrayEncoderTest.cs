using System;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Pqc.Math.Ntru.Polynomial;
using Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.Test;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Util.Test
{

	public class ArrayEncoderTest : SimpleTest
	{
		public override string Name => "ArrayEncoder";

		public void testEncodeDecodeModQ()
		{
			int[] coeffs = PolynomialGenerator.GenerateRandom(1000, 2048).coeffs;
			byte[] data = ArrayEncoder.EncodeModQ(coeffs, 2048);
			int[] coeffs2 = ArrayEncoder.DecodeModQ(data, 1000, 2048);
			Assert.True(coeffs.SequenceEqual(coeffs2));
		}

		public void testEncodeDecodeMod3Sves()
		{
			Random rng = new Random();
			byte[] data = new byte[180];
			rng.NextBytes(data);
			int[] coeffs = ArrayEncoder.DecodeMod3Sves(data, 960);
			byte[] data2 = ArrayEncoder.EncodeMod3Sves(coeffs);
			Assert.True(data.SequenceEqual(data2));
		}

		public void testEncodeDecodeMod3Tight()
		{
			SecureRandom random = new SecureRandom();

			int[] coeffs = DenseTernaryPolynomial.GenerateRandom(1000, random).coeffs;
			byte[] data = ArrayEncoder.EncodeMod3Tight(coeffs);
			int[] coeffs2 = ArrayEncoder.DecodeMod3Tight(data, 1000);
			Assert.True(coeffs.SequenceEqual(coeffs2));
		}

		[Test]
		public override void PerformTest()
		{
			testEncodeDecodeMod3Tight();
			testEncodeDecodeMod3Sves();
			testEncodeDecodeModQ();
		}
	}
}