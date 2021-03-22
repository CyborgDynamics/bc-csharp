using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Util
{

	/**
	 * Converts a coefficient array to a compact byte array and vice versa.
	 */
	public class ArrayEncoder
	{
		/**
		 * Bit string to coefficient conversion table from P1363.1. Also found at
		 * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
		 * <p>
		 * Convert each three-bit quantity to two ternary coefficients as follows, and concatenate the resulting
		 * ternary quantities to obtain [the output].
		 * </p><p>
		 * <code>
		 * {0, 0, 0} -> {0, 0}<br/>
		 * {0, 0, 1} -> {0, 1}<br/>
		 * {0, 1, 0} -> {0, -1}<br/>
		 * {0, 1, 1} -> {1, 0}<br/>
		 * {1, 0, 0} -> {1, 1}<br/>
		 * {1, 0, 1} -> {1, -1}<br/>
		 * {1, 1, 0} -> {-1, 0}<br/>
		 * {1, 1, 1} -> {-1, 1}<br/>
		 * </code>
		 * </p>
		 */
		private static int[] COEFF1_TABLE = { 0, 0, 0, 1, 1, 1, -1, -1 };
		private static int[] COEFF2_TABLE = { 0, 1, -1, 0, 1, -1, 0, 1 };
		/**
		 * Coefficient to bit string conversion table from P1363.1. Also found at
		 * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
		 * <p>
		 * Convert each set of two ternary coefficients to three bits as follows, and concatenate the resulting bit
		 * quantities to obtain [the output]:
		 * </p><p>
		 * <code>
		 * {-1, -1} -> set "fail" to 1 and set bit string to {1, 1, 1}
		 * {-1, 0} -> {1, 1, 0}<br/>
		 * {-1, 1} -> {1, 1, 1}<br/>
		 * {0, -1} -> {0, 1, 0}<br/>
		 * {0, 0} -> {0, 0, 0}<br/>
		 * {0, 1} -> {0, 0, 1}<br/>
		 * {1, -1} -> {1, 0, 1}<br/>
		 * {1, 0} -> {0, 1, 1}<br/>
		 * {1, 1} -> {1, 0, 0}<br/>
		 * </code>   \
		 * </p>
		 */
		private static int[] BIT1_TABLE = { 1, 1, 1, 0, 0, 0, 1, 0, 1 };
		private static int[] BIT2_TABLE = { 1, 1, 1, 1, 0, 0, 0, 1, 0 };
		private static int[] BIT3_TABLE = { 1, 0, 1, 0, 0, 1, 1, 1, 0 };

		/**
		 * Encodes an int array whose elements are between 0 and <code>q</code>,
		 * to a byte array leaving no gaps between bits.<br>
		 * <code>q</code> must be a power of 2.
		 *
		 * @param a the input array
		 * @param q the modulus
		 * @return the encoded array
		 */
		public static byte[] EncodeModQ(int[] a, int q)
		{
			int bitsPerCoeff = 31 - Integers.NumberOfLeadingZeros(q);
			int numBits = a.Length * bitsPerCoeff;
			int numBytes = (numBits + 7) / 8;
			byte[] data = new byte[numBytes];
			int bitIndex = 0;
			int byteIndex = 0;
			for (int i = 0; i < a.Length; i++)
			{
				for (int j = 0; j < bitsPerCoeff; j++)
				{
					int currentBit = (a[i] >> j) & 1;
					data[byteIndex] = (byte)(data[byteIndex] | currentBit << bitIndex);
					if (bitIndex == 7)
					{
						bitIndex = 0;
						byteIndex++;
					}
					else
					{
						bitIndex++;
					}
				}
			}
			return data;
		}

		/**
		 * Decodes a <code>byte</code> array encoded with {@link #encodeModQ(int[], int)} back to an <code>int</code> array.<br>
		 * <code>N</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.<br>
		 * Ignores any excess bytes.
		 *
		 * @param data an encoded ternary polynomial
		 * @param N    number of coefficients
		 * @param q
		 * @return an array containing <code>N</code> coefficients between <code>0</code> and <code>q-1</code>
		 */
		public static int[] DecodeModQ(byte[] data, int N, int q)
		{
			int[] coeffs = new int[N];
			int bitsPerCoeff = 31 - Integers.NumberOfLeadingZeros(q);
			int numBits = N * bitsPerCoeff;
			int coeffIndex = 0;
			for (int bitIndex = 0; bitIndex < numBits; bitIndex++)
			{
				if (bitIndex > 0 && bitIndex % bitsPerCoeff == 0)
				{
					coeffIndex++;
				}
				int bit = GetBit(data, bitIndex);
				coeffs[coeffIndex] += bit << (bitIndex % bitsPerCoeff);
			}
			return coeffs;
		}

		/**
		 * Decodes data encoded with {@link #encodeModQ(int[], int)} back to an <code>int</code> array.<br>
		 * <code>N</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.<br>
		 * Ignores any excess bytes.
		 *
		 * @param is an encoded ternary polynomial
		 * @param N  number of coefficients
		 * @param q
		 * @return the decoded polynomial
		 */
		public static int[] DecodeModQ(Stream stream, int N, int q)
		{
			int qBits = 31 - Integers.NumberOfLeadingZeros(q);
			int size = (N * qBits + 7) / 8;
			byte[] arr = Util.ReadFullLength(stream, size);
			return DecodeModQ(arr, N, q);
		}

		/**
		 * Decodes a <code>byte</code> array encoded with {@link #encodeMod3Sves(int[])} back to an <code>int</code> array
		 * with <code>N</code> coefficients between <code>-1</code> and <code>1</code>.<br>
		 * Ignores any excess bytes.<br>
		 * See P1363.1 section 9.2.2.
		 *
		 * @param data an encoded ternary polynomial
		 * @param N    number of coefficients
		 * @return the decoded coefficients
		 */
		public static int[] DecodeMod3Sves(byte[] data, int N)
		{
			int[] coeffs = new int[N];
			int coeffIndex = 0;
			for (int bitIndex = 0; bitIndex < data.Length * 8;)
			{
				int bit1 = GetBit(data, bitIndex++);
				int bit2 = GetBit(data, bitIndex++);
				int bit3 = GetBit(data, bitIndex++);
				int coeffTableIndex = bit1 * 4 + bit2 * 2 + bit3;
				coeffs[coeffIndex++] = COEFF1_TABLE[coeffTableIndex];
				coeffs[coeffIndex++] = COEFF2_TABLE[coeffTableIndex];
				// ignore bytes that can't fit
				if (coeffIndex > N - 2)
				{
					break;
				}
			}
			return coeffs;
		}

		/**
		 * Encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
		 * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer <code>i</code>,
		 * so this method is only safe to use with arrays produced by {@link #decodeMod3Sves(byte[], int)}.<br>
		 * See P1363.1 section 9.2.3.
		 *
		 * @param arr
		 * @return the encoded array
		 */
		public static byte[] EncodeMod3Sves(int[] arr)
		{
			int numBits = (arr.Length * 3 + 1) / 2;
			int numBytes = (numBits + 7) / 8;
			byte[] data = new byte[numBytes];
			int bitIndex = 0;
			int byteIndex = 0;
			for (int i = 0; i < arr.Length / 2 * 2;)
			{   // if length is an odd number, throw away the highest coeff
				int coeff1 = arr[i++] + 1;
				int coeff2 = arr[i++] + 1;
				if (coeff1 == 0 && coeff2 == 0)
				{
					throw new InvalidDataException("Illegal encoding!");
				}
				int bitTableIndex = coeff1 * 3 + coeff2;
				int[] bits = new int[] { BIT1_TABLE[bitTableIndex], BIT2_TABLE[bitTableIndex], BIT3_TABLE[bitTableIndex] };
				for (int j = 0; j < 3; j++)
				{
					//data[byteIndex] = (byte)(bits[j] | bits[j] << bitIndex);
					data[byteIndex] = (byte)(data[byteIndex] | bits[j] << bitIndex);
					if (bitIndex == 7)
					{
						bitIndex = 0;
						byteIndex++;
					}
					else
					{
						bitIndex++;
					}
				}
			}
			return data;
		}

		/**
		 * Encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
		 *
		 * @return the encoded array
		 */
		public static byte[] EncodeMod3Tight(int[] intArray)
		{
			BigInteger sum = BigInteger.Zero;
			for (int i = intArray.Length - 1; i >= 0; i--)
			{
				sum = sum.Multiply(BigInteger.ValueOf(3));
				sum = sum.Add(BigInteger.ValueOf(intArray[i] + 1));
			}

			int size = (BigInteger.ValueOf(3).Pow(intArray.Length).BitLength + 7) / 8;
			byte[] arr = sum.ToByteArray();

			if (arr.Length < size)
			{
				// pad with leading zeros so arr.Length==size
				byte[] arr2 = new byte[size];
				Array.Copy(arr, 0, arr2, size - arr.Length, arr.Length);
				//arr.CopyTo(arr2, 0,);// System.arraycopy(arr, 0, arr2, size - arr.Length, arr.Length);
				return arr2;
			}

			// drop sign bit
			if (arr.Length > size)
			{
				arr = Arrays.CopyOfRange(arr, 1, arr.Length);
			}
			return arr;
		}

		/**
		 * Converts a byte array produced by {@link #encodeMod3Tight(int[])} back to an <code>int</code> array.
		 *
		 * @param b a byte array
		 * @param N number of coefficients
		 * @return the decoded array
		 */
		public static int[] DecodeMod3Tight(byte[] b, int N)
		{
			BigInteger sum = new BigInteger(1, b);
			int[] coeffs = new int[N];
			for (int i = 0; i < N; i++)
			{
				coeffs[i] = sum.Mod(BigInteger.ValueOf(3)).IntValue - 1;
				if (coeffs[i] > 1)
				{
					coeffs[i] -= 3;
				}
				sum = sum.Divide(BigInteger.ValueOf(3));
			}
			return coeffs;
		}

		/**
		 * Converts data produced by {@link #encodeMod3Tight(int[])} back to an <code>int</code> array.
		 *
		 * @param is an input stream containing the data to decode
		 * @param N  number of coefficients
		 * @return the decoded array
		 */
		public static int[] DecodeMod3Tight(Stream stream, int N)
		{
			int size = (int)System.Math.Ceiling(N * System.Math.Log(3) / System.Math.Log(2) / 8);
			byte[] arr = Util.ReadFullLength(stream, size);
			return DecodeMod3Tight(arr, N);
		}

		private static int GetBit(byte[] arr, int bitIndex)
		{
			int byteIndex = bitIndex / 8;
			int arrElem = arr[byteIndex] & 0xFF;
			return (arrElem >> (bitIndex % 8)) & 1;
		}
	}
}