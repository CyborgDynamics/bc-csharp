#region Using directives

using System;
using System.Collections;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Security;

#endregion

namespace Org.BouncyCastle.Pqc.Math.Ntru.Euclid.Test
{

	[TestFixture]
	public class BigIntEuclideanTest : SimpleTest
	{
		public override string Name
		{
			get { return "BigIntEuclidean"; }
		}

		public override void PerformTest()
		{
			BigIntEuclidean r = BigIntEuclidean.Calculate(BigInteger.ValueOf(120), BigInteger.ValueOf(23));
			Assert.AreEqual(BigInteger.ValueOf(-9), r.x);
			Assert.AreEqual(BigInteger.ValueOf(47), r.y);
			Assert.AreEqual(BigInteger.ValueOf(1), r.gcd);

			r = BigIntEuclidean.Calculate(BigInteger.ValueOf(126), BigInteger.ValueOf(231));
			Assert.AreEqual(BigInteger.ValueOf(2), r.x);
			Assert.AreEqual(BigInteger.ValueOf(-1), r.y);
			Assert.AreEqual(BigInteger.ValueOf(21), r.gcd);
		}


		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}

	}
}