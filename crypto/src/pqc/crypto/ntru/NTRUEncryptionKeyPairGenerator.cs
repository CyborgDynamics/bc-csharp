using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math.Field;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Pqc.Math.Ntru.Polynomial;
using Org.BouncyCastle.Pqc.Math.Ntru.Util;

using IPolynomial = Org.BouncyCastle.Pqc.Math.Ntru.Polynomial.IPolynomial;

namespace Org.BouncyCastle.pqc.Crypto.Ntru
{
	public class NTRUEncryptionKeyPairGenerator : IAsymmetricCipherKeyPairGenerator
	{
		private NTRUEncryptionKeyGenerationParameters Parameters;

		
		public AsymmetricCipherKeyPair GenerateKeyPair()
		{
			int N = Parameters.N;
			int q = Parameters.q;
			int df = Parameters.df;
			int df1 = Parameters.df1;
			int df2 = Parameters.df2;
			int df3 = Parameters.df3;
			int dg = Parameters.dg;
			bool fastFp = Parameters.fastFp;
			bool sparse = Parameters.sparse;

			IPolynomial t;
			IntegerPolynomial fq;
			IntegerPolynomial fp = null;

			// choose a random f that is invertible mod 3 and q
			while (true)
			{
				IntegerPolynomial f;

				// choose random t, calculate f and fp
				if (fastFp)
				{
					// if fastFp=true, f is always invertible mod 3
					t = Parameters.polyType == (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? Util.GenerateRandomTernary(N, df, df, sparse, Parameters.Random) : (IPolynomial)ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3, Parameters.Random);
					f = t.ToIntegerPolynomial();
					f.Multiply(3);
					f.coeffs[0] += 1;
				}
				else
				{
					t = Parameters.polyType == (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? Util.GenerateRandomTernary(N, df, df - 1, sparse, Parameters.Random) : (IPolynomial)ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3 - 1, Parameters.Random);
					f = t.ToIntegerPolynomial();
					fp = f.InvertF3();
					if (fp == null)
					{
						continue;
					}
				}

				fq = f.InvertFq(q);
				if (fq == null)
				{
					continue;
				}
				break;
			}

			// if fastFp=true, fp=1
			if (fastFp)
			{
				fp = new IntegerPolynomial(N);
				fp.coeffs[0] = 1;
			}

			// choose a random g that is invertible mod q
			DenseTernaryPolynomial g;
			while (true)
			{
				g = DenseTernaryPolynomial.GenerateRandom(N, dg, dg - 1, Parameters.Random);
				if (g.InvertFq(q) != null)
				{
					break;
				}
			}

			IntegerPolynomial h = g.Multiply(fq, q);
			h.Multiply3(q);
			h.EnsurePositive(q);
			g.Clear();
			fq.Clear();

			NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(h, t, fp, Parameters.GetEncryptionParameters());
			NTRUEncryptionPublicKeyParameters pub = new NTRUEncryptionPublicKeyParameters(h, Parameters.GetEncryptionParameters());
			return new AsymmetricCipherKeyPair(pub, priv);
		}

		public void Init(KeyGenerationParameters parameters)
		{
			Parameters = (NTRUEncryptionKeyGenerationParameters)parameters;
		}
	}
}