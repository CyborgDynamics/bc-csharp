using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Math.Ntru.Euclid;
using Org.BouncyCastle.Pqc.Math.Ntru.Util;

#pragma warning disable CS3005 // Identifier differing only in case is not CLS-compliant
namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
#pragma warning restore CS3005 // Identifier differing only in case is not CLS-compliant
{
#pragma warning disable CS0659 // Type overrides Object.Equals(object o) but does not override Object.GetHashCode()
	public class IntegerPolynomial : IPolynomial
#pragma warning restore CS0659 // Type overrides Object.Equals(object o) but does not override Object.GetHashCode()
	{
		private static int NUM_EQUAL_RESULTANTS = 3;
		/**
		 * Prime numbers &gt; 4500 for resultant computation. Starting them below ~4400 causes incorrect results occasionally.
		 * Fortunately, 4500 is about the optimum number for performance.<br/>
		 * This array contains enough prime numbers so primes never have to be computed on-line for any standard {@link org.bouncycastle.Pqc.crypto.ntru.NTRUSigningParameters}.
		 */
		private static int[] PRIMES = new int[]{
		4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
		4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
		4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
		4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
		4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
		4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
		5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
		5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
		5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
		5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
		5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
		5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,
		5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
		5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
		5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
		5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
		5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,
		5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
		6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
		6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
		6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
		6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
		6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
		6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
		6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
		6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
		6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
		6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
		6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,
		7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
		7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
		7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,
		7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
		7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
		7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
		7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,
		7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
		7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
		7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
		7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017,
		8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111,
		8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219,
		8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291,
		8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387,
		8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501,
		8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597,
		8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677,
		8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741,
		8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831,
		8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929,
		8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011,
		9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109,
		9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199,
		9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283,
		9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377,
		9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439,
		9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533,
		9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631,
		9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733,
		9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811,
		9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887,
		9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973};
		private static List<BigInteger> BIGINT_PRIMES = new List<BigInteger>();


		public IntegerPolynomial()
		{
			BIGINT_PRIMES = new List<BigInteger>();
			for (int i = 0; i != PRIMES.Length; i++)
			{
				BIGINT_PRIMES.Add(BigInteger.ValueOf(PRIMES[i]));
			}
		}


		public int[] coeffs;

		/**
		 * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
		 *
		 * @param N the number of coefficients
		 */
		public IntegerPolynomial(int N)
		{
			coeffs = new int[N];
		}

		/**
		 * Constructs a new polynomial with a given set of coefficients.
		 *
		 * @param coeffs the coefficients
		 */
		public IntegerPolynomial(int[] coeffs)
		{
			this.coeffs = coeffs;
		}

		/**
		 * Constructs a <code>IntegerPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are independent of each other.
		 *
		 * @param p the original polynomial
		 */
		public IntegerPolynomial(BigIntPolynomial p)
		{
			coeffs = new int[p.coeffs.Length];
			for (int i = 0; i < p.coeffs.Length; i++)
			{
				coeffs[i] = p.coeffs[i].IntValue;
			}
		}

		/**
		 * Decodes a byte array to a polynomial with <code>N</code> ternary coefficients<br>
		 * Ignores any excess bytes.
		 *
		 * @param data an encoded ternary polynomial
		 * @param N    number of coefficients
		 * @return the decoded polynomial
		 */
		public static IntegerPolynomial FromBinary3Sves(byte[] data, int N)
		{
			return new IntegerPolynomial(ArrayEncoder.DecodeMod3Sves(data, N));
		}

		/**
		 * Converts a byte array produced by {@link #toBinary3Tight()} to a polynomial.
		 *
		 * @param b a byte array
		 * @param N number of coefficients
		 * @return the decoded polynomial
		 */
		public static IntegerPolynomial FromBinary3Tight(byte[] b, int N)
		{
			return new IntegerPolynomial(ArrayEncoder.DecodeMod3Tight(b, N));
		}

		/**
		 * Reads data produced by {@link #toBinary3Tight()} from an input stream and converts it to a polynomial.
		 *
		 * @param is an input stream
		 * @param N  number of coefficients
		 * @return the decoded polynomial
		 */
		public static IntegerPolynomial FromBinary3Tight(Stream stream, int N)
		{
			return new IntegerPolynomial(ArrayEncoder.DecodeMod3Tight(stream, N));
		}

		/**
		 * Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.<br>
		 * <code>q</code> must be a power of 2.<br>
		 * Ignores any excess bytes.
		 *
		 * @param data an encoded ternary polynomial
		 * @param N    number of coefficients
		 * @param q
		 * @return the decoded polynomial
		 */
		public static IntegerPolynomial FromBinary(byte[] data, int N, int q)
		{
			return new IntegerPolynomial(ArrayEncoder.DecodeModQ(data, N, q));
		}

		/**
		 * Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.<br>
		 * <code>q</code> must be a power of 2.<br>
		 * Ignores any excess bytes.
		 *
		 * @param is an encoded ternary polynomial
		 * @param N  number of coefficients
		 * @param q
		 * @return the decoded polynomial
		 */
		public static IntegerPolynomial FromBinary(Stream stream, int N, int q)
		{
			return new IntegerPolynomial(ArrayEncoder.DecodeModQ(stream, N, q));
		}

		/**
		 * Encodes a polynomial with ternary coefficients to binary.
		 * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer <code>i</code>,
		 * so this method is only safe to use with polynomials produced by <code>fromBinary3Sves()</code>.
		 *
		 * @return the encoded polynomial
		 */
		public byte[] ToBinary3Sves()
		{
			return ArrayEncoder.EncodeMod3Sves(coeffs);
		}

		/**
		 * Converts a polynomial with ternary coefficients to binary.
		 *
		 * @return the encoded polynomial
		 */
		public byte[] ToBinary3Tight()
		{
			BigInteger sum = Constants.BIGINT_ZERO;
			for (int i = coeffs.Length - 1; i >= 0; i--)
			{
				sum = sum.Multiply(BigInteger.ValueOf(3));
				sum = sum.Add(BigInteger.ValueOf(coeffs[i] + 1));
			}

			int size = (BigInteger.ValueOf(3).Pow(coeffs.Length).BitLength + 7) / 8;
			byte[] arr = sum.ToByteArray();

			if (arr.Length < size)
			{
				// pad with leading zeros so arr.Length==size
				byte[] arr2 = new byte[size];
				Array.Copy(arr, 0, arr2, size - arr.Length, arr.Length);
				return arr2;
			}

			if (arr.Length > size)
			{
				byte[] temp = new byte[arr.Length - 1];
				Array.Copy(arr, 1, temp, 0, (arr.Length - 1));
				arr = temp;
			}
			return arr;
		}

		/**
		 * Encodes a polynomial whose coefficients are between 0 and q, to binary. q must be a power of 2.
		 *
		 * @param q
		 * @return the encoded polynomial
		 */
		public byte[] ToBinary(int q)
		{
			return ArrayEncoder.EncodeModQ(coeffs, q);
		}

		/**
		 * Multiplies the polynomial with another, taking the values mod modulus and the indices mod N
		 */
		public IntegerPolynomial Multiply(IntegerPolynomial poly2, int modulus)
		{
			IntegerPolynomial c = Multiply(poly2);
			c.Mod(modulus);
			return c;
		}

		/**
		 * Multiplies the polynomial with another, taking the indices mod N
		 */
		public IntegerPolynomial Multiply(IntegerPolynomial poly2)
		{
			int N = coeffs.Length;
			if (poly2.coeffs.Length != N)
			{
				throw new InvalidDataException("Number of coefficients must be the same");
			}

			IntegerPolynomial c = MultiplyRecursive(poly2);

			if (c.coeffs.Length > N)
			{
				for (int k = N; k < c.coeffs.Length; k++)
				{
					c.coeffs[k - N] += c.coeffs[k];
				}
				int[] myCoeffs = new int[N];
				Array.Copy(c.coeffs, myCoeffs, N);
				c.coeffs = myCoeffs;
			}
			return c;
		}

		public BigIntPolynomial Multiply(BigIntPolynomial poly2)
		{
			return new BigIntPolynomial(this).Multiply(poly2);
		}

		/**
		 * Karazuba multiplication
		 */
		private IntegerPolynomial MultiplyRecursive(IntegerPolynomial poly2)
		{
			int[] a = coeffs;
			int[] b = poly2.coeffs;

			int n = poly2.coeffs.Length;
			if (n <= 32)
			{
				int cn = 2 * n - 1;
				IntegerPolynomial c = new IntegerPolynomial(new int[cn]);
				for (int k = 0; k < cn; k++)
				{
					for (int i = System.Math.Max(0, k - n + 1); i <= System.Math.Min(k, n - 1); i++)
					{
						c.coeffs[k] += b[i] * a[k - i];
					}
				}
				return c;
			}
			else
			{
				int n1 = n / 2;
				int[] a1temp = new int[n1];
				int[] a2temp = new int[n-n1];
				int[] b1temp = new int[n1];
				int[] b2temp = new int[n-n1];

				Array.Copy(a, a1temp, n1);
				Array.Copy(a, n1, a2temp, 0, n-n1);
				Array.Copy(b, b1temp, n1);
				Array.Copy(b, n1, b2temp, 0, n-n1);
				IntegerPolynomial a1 = new IntegerPolynomial(a1temp);
				IntegerPolynomial a2 = new IntegerPolynomial(a2temp);
				IntegerPolynomial b1 = new IntegerPolynomial(b1temp);
				IntegerPolynomial b2 = new IntegerPolynomial(b2temp);

				IntegerPolynomial A = (IntegerPolynomial)a1.Clone();
				A.Add(a2);
				IntegerPolynomial B = (IntegerPolynomial)b1.Clone();
				B.Add(b2);

				IntegerPolynomial c1 = a1.MultiplyRecursive(b1);
				IntegerPolynomial c2 = a2.MultiplyRecursive(b2);
				IntegerPolynomial c3 = A.MultiplyRecursive(B);
				c3.Sub(c1);
				c3.Sub(c2);

				IntegerPolynomial c = new IntegerPolynomial(2 * n - 1);
				for (int i = 0; i < c1.coeffs.Length; i++)
				{
					c.coeffs[i] = c1.coeffs[i];
				}
				for (int i = 0; i < c3.coeffs.Length; i++)
				{
					c.coeffs[n1 + i] += c3.coeffs[i];
				}
				for (int i = 0; i < c2.coeffs.Length; i++)
				{
					c.coeffs[2 * n1 + i] += c2.coeffs[i];
				}
				return c;
			}
		}

		/**
		 * Computes the inverse mod <code>q; q</code> must be a power of 2.<br>
		 * Returns <code>null</code> if the polynomial is not invertible.
		 *
		 * @param q the modulus
		 * @return a new polynomial
		 */
		public IntegerPolynomial InvertFq(int q)
		{
			int N = coeffs.Length;
			int k = 0;
			IntegerPolynomial b = new IntegerPolynomial(N + 1);
			b.coeffs[0] = 1;
			IntegerPolynomial c = new IntegerPolynomial(N + 1);
			IntegerPolynomial f = new IntegerPolynomial(N + 1);
			Array.Copy(coeffs, f.coeffs, N);
			f.ModPositive(2);
			// set g(x) = x^N − 1
			IntegerPolynomial g = new IntegerPolynomial(N + 1);
			g.coeffs[0] = 1;
			g.coeffs[N] = 1;
			while (true)
			{
				while (f.coeffs[0] == 0)
				{
					for (int i = 1; i <= N; i++)
					{
						f.coeffs[i - 1] = f.coeffs[i];   // f(x) = f(x) / x
						c.coeffs[N + 1 - i] = c.coeffs[N - i];   // c(x) = c(x) * x
					}
					f.coeffs[N] = 0;
					c.coeffs[0] = 0;
					k++;
					if (f.EqualsZero())
					{
						return null;   // not invertible
					}
				}
				if (f.EqualsOne())
				{
					break;
				}
				if (f.Degree() < g.Degree())
				{
					// exchange f and g
					IntegerPolynomial temp = f;
					f = g;
					g = temp;
					// exchange b and c
					temp = b;
					b = c;
					c = temp;
				}
				f.Add(g, 2);
				b.Add(c, 2);
			}

			if (b.coeffs[N] != 0)
			{
				return null;
			}
			// Fq(x) = x^(N-k) * b(x)
			IntegerPolynomial Fq = new IntegerPolynomial(N);
			int j = 0;
			k %= N;
			for (int i = N - 1; i >= 0; i--)
			{
				j = i - k;
				if (j < 0)
				{
					j += N;
				}
				Fq.coeffs[j] = b.coeffs[i];
			}

			return Mod2ToModq(Fq, q);
		}

		/**
		 * Computes the inverse mod q from the inverse mod 2
		 *
		 * @param Fq
		 * @param q
		 * @return The inverse of this polynomial mod q
		 */
		private IntegerPolynomial Mod2ToModq(IntegerPolynomial Fq, int q)
		{
			//if (Util.is64BitJVM() && q == 2048)
				if (true && q == 2048)
				{
					LongPolynomial2 thisLong = new LongPolynomial2(this);
					LongPolynomial2 FqLong = new LongPolynomial2(Fq);
					int v = 2;
					while (v < q)
					{
						v *= 2;
						LongPolynomial2 temp = (LongPolynomial2)FqLong.Clone();
						temp.mult2And(v - 1);
						FqLong = thisLong.Multiply(FqLong).Multiply(FqLong);
						temp.SubAnd(FqLong, v - 1);
						FqLong = temp;
					}
					return FqLong.ToIntegerPolynomial();
				}
				else
				{
					int v = 2;
					while (v < q)
					{
						v *= 2;
						int[] copy = new int[Fq.coeffs.Length];
						Array.Copy(Fq.coeffs, copy, Fq.coeffs.Length);
						IntegerPolynomial temp = new IntegerPolynomial(copy);
						temp.Multiply2(v);
						Fq = Multiply(Fq, v).Multiply(Fq, v);
						temp.Sub(Fq, v);
						Fq = temp;
					}
					return Fq;
				}
		}

		/**
		 * Computes the inverse mod 3.
		 * Returns <code>null</code> if the polynomial is not invertible.
		 *
		 * @return a new polynomial
		 */
		public IntegerPolynomial InvertF3()
		{
			int N = coeffs.Length;
			int k = 0;
			IntegerPolynomial b = new IntegerPolynomial(N + 1);
			b.coeffs[0] = 1;
			IntegerPolynomial c = new IntegerPolynomial(N + 1);
			IntegerPolynomial f = new IntegerPolynomial(N + 1);
			Array.Copy(coeffs, f.coeffs, N);
			f.ModPositive(3);
			// set g(x) = x^N − 1
			IntegerPolynomial g = new IntegerPolynomial(N + 1);
			g.coeffs[0] = -1;
			g.coeffs[N] = 1;
			while (true)
			{
				while (f.coeffs[0] == 0)
				{
					for (int i = 1; i <= N; i++)
					{
						f.coeffs[i - 1] = f.coeffs[i];   // f(x) = f(x) / x
						c.coeffs[N + 1 - i] = c.coeffs[N - i];   // c(x) = c(x) * x
					}
					f.coeffs[N] = 0;
					c.coeffs[0] = 0;
					k++;
					if (f.EqualsZero())
					{
						return null;   // not invertible
					}
				}
				if (f.EqualsAbsOne())
				{
					break;
				}
				if (f.Degree() < g.Degree())
				{
					// exchange f and g
					IntegerPolynomial temp = f;
					f = g;
					g = temp;
					// exchange b and c
					temp = b;
					b = c;
					c = temp;
				}
				if (f.coeffs[0] == g.coeffs[0])
				{
					f.Sub(g, 3);
					b.Sub(c, 3);
				}
				else
				{
					f.Add(g, 3);
					b.Add(c, 3);
				}
			}

			if (b.coeffs[N] != 0)
			{
				return null;
			}
			// Fp(x) = [+-] x^(N-k) * b(x)
			IntegerPolynomial Fp = new IntegerPolynomial(N);
			int j = 0;
			k %= N;
			for (int i = N - 1; i >= 0; i--)
			{
				j = i - k;
				if (j < 0)
				{
					j += N;
				}
				Fp.coeffs[j] = f.coeffs[0] * b.coeffs[i];
			}

			Fp.EnsurePositive(3);
			return Fp;
		}

		/**
		 * Resultant of this polynomial with <code>x^n-1</code> using a probabilistic algorithm.
		 * <p>
		 * Unlike EESS, this implementation does not compute all resultants modulo primes
		 * such that their product exceeds the maximum possible resultant, but rather stops
		 * when <code>NUM_EQUAL_RESULTANTS</code> consecutive modular resultants are equal.<br>
		 * This means the return value may be incorrect. Experiments show this happens in
		 * about 1 out of 100 cases when <code>N=439</code> and <code>NUM_EQUAL_RESULTANTS=2</code>,
		 * so the likelyhood of leaving the loop too early is <code>(1/100)^(NUM_EQUAL_RESULTANTS-1)</code>.
		 * <p>
		 * Because of the above, callers must verify the output and try a different polynomial if necessary.
		 *
		 * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
		 */
		public Resultant Resultant()
		{
			int N = coeffs.Length;

			// Compute resultants modulo prime numbers. Continue until NUM_EQUAL_RESULTANTS consecutive modular resultants are equal.
			LinkedList<ModularResultant> modResultants = new LinkedList<ModularResultant>();
			BigInteger pProd = Constants.BIGINT_ONE;
			BigInteger res = Constants.BIGINT_ONE;
			int numEqual = 1;   // number of consecutive modular resultants equal to each other

			PrimeGenerator primes = new PrimeGenerator();
			BigInteger pProd2;
			BigInteger pProd2n;
			while (true)
			{
				BigInteger prime = primes.nextPrime();
				ModularResultant crr = Resultant(prime.IntValue);
				modResultants.AddLast(crr); //Was just add in Java

				BigInteger temp = pProd.Multiply(prime);
				BigIntEuclidean er = BigIntEuclidean.Calculate(prime, pProd);
				BigInteger resPrev = res;
				res = res.Multiply(er.x.Multiply(prime));
				BigInteger res2 = crr.Res.Multiply(er.y.Multiply(pProd));
				res = res.Add(res2).Mod(temp);
				pProd = temp;

				pProd2 = pProd.Divide(BigInteger.ValueOf(2));
				pProd2n = pProd2.Negate();
				if (res.CompareTo(pProd2) > 0)
				{
					res = res.Subtract(pProd);
				}
				else if (res.CompareTo(pProd2n) < 0)
				{
					res = res.Add(pProd);
				}

				if (res.Equals(resPrev))
				{
					numEqual++;
					if (numEqual >= NUM_EQUAL_RESULTANTS)
					{
						break;
					}
					
				}
				else
				{
					numEqual = 1;
				}
			}

			// Combine modular rho's to obtain the final rho.
			// For efficiency, first combine all pairs of small resultants to bigger resultants,
			// then combine pairs of those, etc. until only one is left.
			while (modResultants.Count > 1)
			{
				ModularResultant modRes1 = modResultants.First.Value;
				modResultants.RemoveFirst();
				ModularResultant modRes2 = modResultants.First.Value;
				modResultants.RemoveFirst();
				ModularResultant modRes3 = ModularResultant.CombineRho(modRes1, modRes2);
				modResultants.AddLast(modRes3);
			}
			BigIntPolynomial rhoP = modResultants.First.Value.Rho;

			pProd2 = pProd.Divide(BigInteger.ValueOf(2));
			pProd2n = pProd2.Negate();
			if (res.CompareTo(pProd2) > 0)
			{
				res = res.Subtract(pProd);
			}
			if (res.CompareTo(pProd2n) < 0)
			{
				res = res.Add(pProd);
			}

			for (int i = 0; i < N; i++)
			{
				BigInteger c = rhoP.coeffs[i];
				if (c.CompareTo(pProd2) > 0)
				{
					rhoP.coeffs[i] = c.Subtract(pProd);
				}
				if (c.CompareTo(pProd2n) < 0)
				{
					rhoP.coeffs[i] = c.Add(pProd);
				}
			}

			return new Resultant(rhoP, res);
		}

		/**
		 * Multithreaded version of {@link #resultant()}.
		 *
		 * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
		 */
		/* Taking out Async for now, harder problem than just translating. 
		public async Task<Resultant> ResultantMultiThread()
		{
			int N = coeffs.Length;

			// upper bound for resultant(f, g) = ||f, 2||^deg(g) * ||g, 2||^deg(f) = squaresum(f)^(N/2) * 2^(deg(f)/2) because g(x)=x^N-1
			// see http://jondalon.mathematik.uni-osnabrueck.de/staff/phpages/brunsw/CompAlg.pdf chapter 3
			BigInteger max = squareSum().pow((N + 1) / 2);
			max = max.multiply(BigInteger.ValueOf(2).pow((degree() + 1) / 2));
			BigInteger max2 = max.multiply(BigInteger.ValueOf(2));

			// compute resultants modulo prime numbers
			BigInteger prime = BigInteger.ValueOf(10000);
			BigInteger pProd = Constants.BIGINT_ONE;
			LinkedBlockingQueue<Task<ModularResultant>> resultantTasks = new LinkedBlockingQueue<Task<ModularResultant>>();
			Iterator<BigInteger> primes = BIGINT_PRIMES.Iterator();
			ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
			while (pProd.CompareTo(max2) < 0)
			{
				if (primes.hasNext())
				{
					prime = primes.next();
				}
				else
				{
					prime = prime.NextProbablePrime();
				}
				Task<ModularResultant> task = executor.submit(new ModResultantTask(prime.IntValue));
				resultantTasks.add(task);
				pProd = pProd.Multiply(prime);
			}

			// Combine modular resultants to obtain the resultant.
			// For efficiency, first combine all pairs of small resultants to bigger resultants,
			// then combine pairs of those, etc. until only one is left.
			ModularResultant overallResultant = null;
			while (!resultantTasks.isEmpty())
			{
				try
				{
					Task<ModularResultant> modRes1 = resultantTasks.take();
					Task<ModularResultant> modRes2 = resultantTasks.poll();
					if (modRes2 == null)
					{
						// modRes1 is the only one left
						overallResultant = await modRes1; //modRes1..get();
						break;
					}
					Task<ModularResultant> newTask = executor.submit(new CombineTask(modRes1.get(), modRes2.get()));
					resultantTasks.add(newTask);
				}
				catch (Exception e)
				{
					throw new InvalidOperationException(e.ToString());
				}
			}
			executor.shutdown();
			BigInteger res = overallResultant.res;
			BigIntPolynomial rhoP = overallResultant.rho;

			BigInteger pProd2 = pProd.divide(BigInteger.ValueOf(2));
			BigInteger pProd2n = pProd2.negate();

			if (res.compareTo(pProd2) > 0)
			{
				res = res.subtract(pProd);
			}
			if (res.compareTo(pProd2n) < 0)
			{
				res = res.add(pProd);
			}

			for (int i = 0; i < N; i++)
			{
				BigInteger c = rhoP.coeffs[i];
				if (c.compareTo(pProd2) > 0)
				{
					rhoP.coeffs[i] = c.subtract(pProd);
				}
				if (c.compareTo(pProd2n) < 0)
				{
					rhoP.coeffs[i] = c.add(pProd);
				}
			}

			return new Resultant(rhoP, res);
		}
		*/
		/**
		 * Resultant of this polynomial with <code>x^n-1 mod p</code>.
		 *
		 * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1) mod p</code> for some integer <code>t</code>.
		 */
		public ModularResultant Resultant(int p)
		{
			// Add a coefficient as the following operations involve polynomials of degree deg(f)+1
			int[] fcoeffs = new int[coeffs.Length + 1];
			Array.Copy(coeffs, fcoeffs, coeffs.Length);
			IntegerPolynomial f = new IntegerPolynomial(fcoeffs);
			int N = fcoeffs.Length;

			IntegerPolynomial a = new IntegerPolynomial(N);
			a.coeffs[0] = -1;
			a.coeffs[N - 1] = 1;
			IntegerPolynomial b = new IntegerPolynomial(f.coeffs);
			IntegerPolynomial v1 = new IntegerPolynomial(N);
			IntegerPolynomial v2 = new IntegerPolynomial(N);
			v2.coeffs[0] = 1;
			int da = N - 1;
			int db = b.Degree();
			int ta = da;
			int c = 0;
			int r = 1;
			while (db > 0)
			{
				c = Util.Util.Invert(b.coeffs[db], p);
				c = (c * a.coeffs[da]) % p;
				a.MultShiftSub(b, c, da - db, p);
				v1.MultShiftSub(v2, c, da - db, p);

				da = a.Degree();
				if (da < db)
				{
					r *= Util.Util.Pow(b.coeffs[db], ta - da, p);
					r %= p;
					if (ta % 2 == 1 && db % 2 == 1)
					{
						r = (-r) % p;
					}
					IntegerPolynomial temp = a;
					a = b;
					b = temp;
					int tempdeg = da;
					da = db;
					temp = v1;
					v1 = v2;
					v2 = temp;
					ta = db;
					db = tempdeg;
				}
			}
			r *= Util.Util.Pow(b.coeffs[0], da, p);
			r %= p;
			c = Util.Util.Invert(b.coeffs[0], p);
			v2.Multiply(c);
			v2.Mod(p);
			v2.Multiply(r);
			v2.Mod(p);

			// drop the highest coefficient so #coeffs matches the original input
			int[] newCoeffs = new int[v2.coeffs.Length - 1];
			Array.Copy(v2.coeffs, newCoeffs, v2.coeffs.Length - 1);
			v2.coeffs = newCoeffs;
			return new ModularResultant(new BigIntPolynomial(v2), BigInteger.ValueOf(r), BigInteger.ValueOf(p));
		}

		/**
		 * Computes <code>this-b*c*(x^k) mod p</code> and stores the result in this polynomial.<br/>
		 * See steps 4a,4b in EESS algorithm 2.2.7.1.
		 *
		 * @param b
		 * @param c
		 * @param k
		 * @param p
		 */
		private void MultShiftSub(IntegerPolynomial b, int c, int k, int p)
		{
			int N = coeffs.Length;
			for (int i = k; i < N; i++)
			{
				coeffs[i] = (coeffs[i] - b.coeffs[i - k] * c) % p;
			}
		}

		/**
		 * Adds the squares of all coefficients.
		 *
		 * @return the sum of squares
		 */
		private BigInteger SquareSum()
		{
			BigInteger sum = Constants.BIGINT_ZERO;
			for (int i = 0; i < coeffs.Length; i++)
			{
				sum = sum.Add(BigInteger.ValueOf(coeffs[i] * coeffs[i]));
			}
			return sum;
		}

		/**
		 * Returns the degree of the polynomial
		 *
		 * @return the degree
		 */
		int Degree()
		{
			int degree = coeffs.Length - 1;
			while (degree > 0 && coeffs[degree] == 0)
			{
				degree--;
			}
			return degree;
		}

		/**
		 * Adds another polynomial which can have a different number of coefficients,
		 * and takes the coefficient values mod <code>modulus</code>.
		 *
		 * @param b another polynomial
		 */
		public void Add(IntegerPolynomial b, int modulus)
		{
			Add(b);
			Mod(modulus);
		}

		/**
		 * Adds another polynomial which can have a different number of coefficients.
		 *
		 * @param b another polynomial
		 */
		public void Add(IntegerPolynomial b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				int[] temp = new int[b.coeffs.Length];
				Array.Copy(coeffs, temp, coeffs.Length);
				coeffs = temp;
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] += b.coeffs[i];
			}
		}

		/**
		 * Subtracts another polynomial which can have a different number of coefficients,
		 * and takes the coefficient values mod <code>modulus</code>.
		 *
		 * @param b another polynomial
		 */
		public void Sub(IntegerPolynomial b, int modulus)
		{
			Sub(b);
			Mod(modulus);
		}

		/**
		 * Subtracts another polynomial which can have a different number of coefficients.
		 *
		 * @param b another polynomial
		 */
		public void Sub(IntegerPolynomial b)
		{
			if (b.coeffs.Length > coeffs.Length)
			{
				Array.Copy(coeffs, coeffs, b.coeffs.Length);
			}
			for (int i = 0; i < b.coeffs.Length; i++)
			{
				coeffs[i] -= b.coeffs[i];
			}
		}

		/**
		 * Subtracts a <code>int</code> from each coefficient. Does not return a new polynomial but modifies this polynomial.
		 *
		 * @param b
		 */
		void Sub(int b)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] -= b;
			}
		}

		/**
		 * Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
		 *
		 * @param factor
		 */
		public void Multiply(int factor)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] *= factor;
			}
		}

		/**
		 * Multiplies each coefficient by a 2 and applies a modulus. Does not return a new polynomial but modifies this polynomial.
		 *
		 * @param modulus a modulus
		 */
		private void Multiply2(int modulus)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] *= 2;
				coeffs[i] %= modulus;
			}
		}

		/**
		 * Multiplies each coefficient by a 2 and applies a modulus. Does not return a new polynomial but modifies this polynomial.
		 *
		 * @param modulus a modulus
		 */
		public void Multiply3(int modulus)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] *= 3;
				coeffs[i] %= modulus;
			}
		}

		/**
		 * Divides each coefficient by <code>k</code> and rounds to the nearest integer. Does not return a new polynomial but modifies this polynomial.
		 *
		 * @param k the divisor
		 */
		public void Divide(int k)
		{
			int k2 = (k + 1) / 2;
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] += coeffs[i] > 0 ? k2 : -k2;
				coeffs[i] /= k;
			}
		}

		/**
		 * Takes each coefficient modulo 3 such that all coefficients are ternary.
		 */
		public void Mod3()
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] %= 3;
				if (coeffs[i] > 1)
				{
					coeffs[i] -= 3;
				}
				if (coeffs[i] < -1)
				{
					coeffs[i] += 3;
				}
			}
		}

		/**
		 * Ensures all coefficients are between 0 and <code>modulus-1</code>
		 *
		 * @param modulus a modulus
		 */
		public void ModPositive(int modulus)
		{
			Mod(modulus);
			EnsurePositive(modulus);
		}

		/**
		 * Reduces all coefficients to the interval [-modulus/2, modulus/2)
		 */
		void ModCenter(int modulus)
		{
			Mod(modulus);
			for (int j = 0; j < coeffs.Length; j++)
			{
				while (coeffs[j] < modulus / 2)
				{
					coeffs[j] += modulus;
				}
				while (coeffs[j] >= modulus / 2)
				{
					coeffs[j] -= modulus;
				}
			}
		}

		/**
		 * Takes each coefficient modulo <code>modulus</code>.
		 */
		public void Mod(int modulus)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] %= modulus;
			}
		}

		/**
		 * Adds <code>modulus</code> until all coefficients are above 0.
		 *
		 * @param modulus a modulus
		 */
		public void EnsurePositive(int modulus)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				while (coeffs[i] < 0)
				{
					coeffs[i] += modulus;
				}
			}
		}

		/**
		 * Computes the centered euclidean norm of the polynomial.
		 *
		 * @param q a modulus
		 * @return the centered norm
		 */
		public long CenteredNormSq(int q)
		{
			int N = coeffs.Length;
			IntegerPolynomial p = (IntegerPolynomial)Clone();
			p.ShiftGap(q);

			long sum = 0;
			long sqSum = 0;
			for (int i = 0; i != p.coeffs.Length; i++)
			{
				int c = p.coeffs[i];
				sum += c;
				sqSum += c * c;
			}

			long centeredNormSq = sqSum - sum * sum / N;
			return centeredNormSq;
		}

		/**
		 * Shifts all coefficients so the largest gap is centered around <code>-q/2</code>.
		 *
		 * @param q a modulus
		 */
		void ShiftGap(int q)
		{
			ModCenter(q);

			int[] sorted = new int[coeffs.Length];
			Array.Copy(coeffs, sorted, coeffs.Length);

			Sort(sorted);

			int maxrange = 0;
			int maxrangeStart = 0;
			for (int i = 0; i < sorted.Length - 1; i++)
			{
				int range = sorted[i + 1] - sorted[i];
				if (range > maxrange)
				{
					maxrange = range;
					maxrangeStart = sorted[i];
				}
			}

			int pmin = sorted[0];
			int pmax = sorted[sorted.Length - 1];

			int j = q - pmax + pmin;
			int shift;
			if (j > maxrange)
			{
				shift = (pmax + pmin) / 2;
			}
			else
			{
				shift = maxrangeStart + maxrange / 2 + q / 2;
			}

			Sub(shift);
		}

		private void Sort(int[] ints)
		{
			bool swap = true;

			while (swap)
			{
				swap = false;
				for (int i = 0; i != ints.Length - 1; i++)
				{
					if (ints[i] > ints[i + 1])
					{
						int tmp = ints[i];
						ints[i] = ints[i + 1];
						ints[i + 1] = tmp;
						swap = true;
					}
				}
			}
		}

		/**
		 * Shifts the values of all coefficients to the interval <code>[-q/2, q/2]</code>.
		 *
		 * @param q a modulus
		 */
		public void Center0(int q)
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				while (coeffs[i] < -q / 2)
				{
					coeffs[i] += q;
				}
				while (coeffs[i] > q / 2)
				{
					coeffs[i] -= q;
				}
			}
		}

		/**
		 * Returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
		 *
		 * @return the sum of all coefficients
		 */
		public int SumCoeffs()
		{
			int sum = 0;
			for (int i = 0; i < coeffs.Length; i++)
			{
				sum += coeffs[i];
			}
			return sum;
		}

		/**
		 * Tests if <code>p(x) = 0</code>.
		 *
		 * @return true iff all coefficients are zeros
		 */
		private bool EqualsZero()
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				if (coeffs[i] != 0)
				{
					return false;
				}
			}
			return true;
		}

		/**
		 * Tests if <code>p(x) = 1</code>.
		 *
		 * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1
		 */
		public bool EqualsOne()
		{
			for (int i = 1; i < coeffs.Length; i++)
			{
				if (coeffs[i] != 0)
				{
					return false;
				}
			}
			return coeffs[0] == 1;
		}

		/**
		 * Tests if <code>|p(x)| = 1</code>.
		 *
		 * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1 or -1
		 */
		private bool EqualsAbsOne()
		{
			for (int i = 1; i < coeffs.Length; i++)
			{
				if (coeffs[i] != 0)
				{
					return false;
				}
			}
			return System.Math.Abs(coeffs[0]) == 1;
		}

		/**
		 * Counts the number of coefficients equal to an integer
		 *
		 * @param value an integer
		 * @return the number of coefficients equal to <code>value</code>
		 */
		public int Count(int value)
		{
			int count = 0;
			for (int i = 0; i != coeffs.Length; i++)
			{
				if (coeffs[i] == value)
				{
					count++;
				}
			}
			return count;
		}

		/**
		 * Multiplication by <code>X</code> in <code>Z[X]/Z[X^n-1]</code>.
		 */
		public void Rotate1()
		{
			int clast = coeffs[coeffs.Length - 1];
			for (int i = coeffs.Length - 1; i > 0; i--)
			{
				coeffs[i] = coeffs[i - 1];
			}
			coeffs[0] = clast;
		}

		public void Clear()
		{
			for (int i = 0; i < coeffs.Length; i++)
			{
				coeffs[i] = 0;
			}
		}

		public IntegerPolynomial ToIntegerPolynomial()
		{
			return (IntegerPolynomial)Clone();
		}

		public object Clone()
		{
			int[] temp = new int[coeffs.Length];
			Array.Copy(coeffs, temp, coeffs.Length);
			return new IntegerPolynomial(temp);
		}

		public override bool Equals(object obj)
		{
			if (obj.GetType() == typeof(IntegerPolynomial))
			{
				return Array.Equals(coeffs, ((IntegerPolynomial)obj).coeffs);
			}

			else
			{
				return false;
			}
		}

		/**
		 * Calls {@link IntegerPolynomial#resultant(int)
		 */
		private class ModResultantTask : ModularResultant
		{

			private int modulus;

			public ModResultantTask(int modulus)
			{
				this.modulus = modulus;
			}

			public ModularResultant Call()
			{
				return new ModularResultant(modulus);
			}
		}

		/**
		 * Calls {@link ModularResultant#combineRho(ModularResultant, ModularResultant)
		 */
		internal class CombineTask : ModularResultant
		{

			private ModularResultant modRes1;
			private ModularResultant modRes2;

			public CombineTask(ModularResultant modRes1, ModularResultant modRes2)
			{
				this.modRes1 = modRes1;
				this.modRes2 = modRes2;
			}

			public ModularResultant call()
			{
				return ModularResultant.CombineRho(modRes1, modRes2);
			}
		}

		public class PrimeGenerator
		{
			private int index = 0;
			private BigInteger prime = BigInteger.Zero;

			public BigInteger nextPrime()
			{
				if (index < BIGINT_PRIMES.Count)
				{
					prime = (BigInteger)BIGINT_PRIMES[index++];
				}
				else
				{
					prime = prime.NextProbablePrime();
				}

				return prime;
			}
		}
	}
}