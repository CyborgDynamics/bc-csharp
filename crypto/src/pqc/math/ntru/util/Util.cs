using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Pqc.Math.Ntru.Euclid;
using Org.BouncyCastle.Pqc.Math.Ntru.Polynomial;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Util
{
	public class Util
	{
		//private static volatile bool IS_64_BITNESS_KNOWN;
		//private static volatile bool IS_64_BIT_JVM;

		/**
		 * Calculates the inverse of n mod modulus
		 */
		public static int Invert(int n, int modulus)
		{
			n %= modulus;
			if (n < 0)
			{
				n += modulus;
			}
			return IntEuclidean.Calculate(n, modulus).x;
		}

		/**
		 * Calculates a^b mod modulus
		 */
		public static int Pow(int a, int b, int modulus)
		{
			int p = 1;
			for (int i = 0; i < b; i++)
			{
				p = (p * a) % modulus;
			}
			return p;
		}

		/**
		 * Calculates a^b mod modulus
		 */
		public static long Pow(long a, int b, long modulus)
		{
			long p = 1;
			for (int i = 0; i < b; i++)
			{
				p = (p * a) % modulus;
			}
			return p;
		}

		/**
		 * Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
		 * numNegOnes int equal to -1, and the rest equal to 0.
		 *
		 * @param N
		 * @param numOnes
		 * @param numNegOnes
		 * @param sparse     whether to create a {@link SparseTernaryPolynomial} or {@link DenseTernaryPolynomial}
		 * @return a ternary polynomial
		 */
		public static ITernaryPolynomial GenerateRandomTernary(int N, int numOnes, int numNegOnes, bool sparse, SecureRandom random)
		{
			if (sparse)
			{
				return SparseTernaryPolynomial.GenerateRandom(N, numOnes, numNegOnes, random);
			}
			else
			{
				return DenseTernaryPolynomial.GenerateRandom(N, numOnes, numNegOnes, random);
			}
		}

		/**
		 * Generates an array containing numOnes ints equal to 1,
		 * numNegOnes int equal to -1, and the rest equal to 0.
		 *
		 * @param N
		 * @param numOnes
		 * @param numNegOnes
		 * @return an array of integers
		 */
		public static int[] GenerateRandomTernary(int N, int numOnes, int numNegOnes, SecureRandom random)
		{
			int one = 1;// Integers.ValueOf(1);
			int minusOne = -1; // Integer minusOne = Integers.ValueOf(-1);
			int zero = 0; // Integer zero = Integers.ValueOf(0);

			List<int> list = new List<int>();
			for (int i = 0; i < numOnes; i++)
			{
				list.Add(one);
			}
			for (int i = 0; i < numNegOnes; i++)
			{
				list.Add(minusOne);
			}
			while (list.Count < N)
			{
				list.Add(zero);
			}

			list = Shuffle(list, random);

			int[] arr = new int[N];
			for (int i = 0; i < N; i++)
			{
				arr[i] = (list[i]);
			}
			return arr;
		}

		private static List<int> Shuffle(List<int> list, SecureRandom random)
		{
			List<int> randomList = new List<int>();

			int randomIndex = 0;
			while (list.Count > 0)
			{
				randomIndex = random.Next(0, list.Count); //Choose a random object in the list
				randomList.Add(list[randomIndex]); //add it to the new, random list
				list.RemoveAt(randomIndex); //remove to avoid duplicates
			}

			return randomList; //return the new random list

		}

		/// We only run in x64
		//public static bool Is64BitJVM()
		//{

		//	if (!IS_64_BITNESS_KNOWN)
		//	{
		//		String arch = System.Con("os.arch");
		//		String sunModel = System.GetProperty("sun.arch.data.model");
		//		IS_64_BIT_JVM = "amd64".Equals(arch) || "x86_64".Equals(arch) || "ppc64".Equals(arch) || "64".Equals(sunModel);
		//		IS_64_BITNESS_KNOWN = true;
		//	}
		//	return IS_64_BIT_JVM;
		//}

		/**
		 * Reads a given number of bytes from an <code>InputStream</code>.
		 * If there are not enough bytes in the stream, an <code>IOException</code>
		 * is thrown.
		 *
		 * @param is
		 * @param length
		 * @return an array of length <code>length</code>
		 * @throws IOException
		 */
		public static byte[] ReadFullLength(Stream stream, int length)

		{

			byte[] arr = new byte[length];
			if (stream.Read(arr, 0, length) != arr.Length)
			{
				throw new IOException("Not enough bytes to read.");
			}
			return arr;
		}
	}
	public static class BitWiseExtensions
	{
		public static int LeadingZeros(this int x)
		{
			const int numIntBits = sizeof(int) * 8; //compile time constant
													//do the smearing
			x |= x >> 1;
			x |= x >> 2;
			x |= x >> 4;
			x |= x >> 8;
			x |= x >> 16;
			//count the ones
			x -= x >> 1 & 0x55555555;
			x = (x >> 2 & 0x33333333) + (x & 0x33333333);
			x = (x >> 4) + x & 0x0f0f0f0f;
			x += x >> 8;
			x += x >> 16;
			return numIntBits - (x & 0x0000003f); //subtract # of 1s from 32
		}

		public static int UnsignedRightShift(this int signed, int places)
		{
			unchecked // just in case of unusual compiler switches; this is the default
			{
				var unsigned = (uint)signed;
				unsigned >>= places;
				return (int)unsigned;
			}
		}

		public static long UnsignedRightShift(this long signed, int places)
		{
			unchecked // just in case of unusual compiler switches; this is the default
			{
				var unsigned = (ulong)signed;
				unsigned >>= places;
				return (long)unsigned;
			}
		}

		public static int HashContents<T>(this IEnumerable<T> enumerable)
		{
			int hash = 0x218A9B2C;
			foreach (var item in enumerable)
			{
				int thisHash = item.GetHashCode();
				//mix up the bits.
				hash = thisHash ^ ((hash << 5) + hash);
			}
			return hash;
		}

		public static void FlatCopyTo(this Array source, Array destination)
		{
			IEnumerator enu = source.GetEnumerator();
			enu.Reset();
			int i = 0;
			while(enu.MoveNext())
			{
				destination.SetValue(enu.Current, i++);
			}
		}
	}
}