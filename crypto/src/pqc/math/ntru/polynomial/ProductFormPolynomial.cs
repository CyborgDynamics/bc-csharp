using System;
using System.IO;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Math.Ntru.Polynomial
{
		/**
	 * A polynomial of the form <code>f1*f2+f3</code>, where
	 * <code>f1,f2,f3</code> are very sparsely populated ternary polynomials.
	 */
	public class ProductFormPolynomial : IPolynomial
	{
		private SparseTernaryPolynomial F1, F2, F3;

		public ProductFormPolynomial(SparseTernaryPolynomial f1, SparseTernaryPolynomial f2, SparseTernaryPolynomial f3)
		{
			F1 = f1;
			F2 = f2;
			F3 = f3;
		}

		public static ProductFormPolynomial GenerateRandom(int N, int df1, int df2, int df3Ones, int df3NegOnes, SecureRandom random)
		{
			SparseTernaryPolynomial f1 = SparseTernaryPolynomial.GenerateRandom(N, df1, df1, random);
			SparseTernaryPolynomial f2 = SparseTernaryPolynomial.GenerateRandom(N, df2, df2, random);
			SparseTernaryPolynomial f3 = SparseTernaryPolynomial.GenerateRandom(N, df3Ones, df3NegOnes, random);
			return new ProductFormPolynomial(f1, f2, f3);
		}

		public static ProductFormPolynomial FromBinary(byte[] data, int N, int df1, int df2, int df3Ones, int df3NegOnes)
		{
			return FromBinary(new MemoryStream(data), N, df1, df2, df3Ones, df3NegOnes);
		}

		public static ProductFormPolynomial FromBinary(Stream stream, int N, int df1, int df2, int df3Ones, int df3NegOnes)
		{
			SparseTernaryPolynomial f1;

			f1 = SparseTernaryPolynomial.FromBinary(stream, N, df1, df1);
			SparseTernaryPolynomial f2 = SparseTernaryPolynomial.FromBinary(stream, N, df2, df2);
			SparseTernaryPolynomial f3 = SparseTernaryPolynomial.FromBinary(stream, N, df3Ones, df3NegOnes);
			return new ProductFormPolynomial(f1, f2, f3);
		}

		public byte[] ToBinary()
		{
			byte[] f1Bin = F1.ToBinary();
			byte[] f2Bin = F2.ToBinary();
			byte[] f3Bin = F3.ToBinary();

			byte[] all = new byte[f1Bin.Length + f2Bin.Length + f3Bin.Length];
			Array.Copy(f1Bin, all, f1Bin.Length);
			Array.Copy(f2Bin, 0, all, f1Bin.Length, f2Bin.Length);
			Array.Copy(f3Bin, 0, all, (f1Bin.Length + f2Bin.Length), f3Bin.Length);
			return all;
		}

		public IntegerPolynomial Multiply(IntegerPolynomial b)
		{
			IntegerPolynomial c = F1.Multiply(b);
			c = F2.Multiply(c);
			c.Add(F3.Multiply(b));
			return c;
		}

		public BigIntPolynomial Multiply(BigIntPolynomial b)
		{
			BigIntPolynomial c = F1.Multiply(b);
			c = F2.Multiply(c);
			c.Add(F3.Multiply(b));
			return c;
		}

		public IntegerPolynomial ToIntegerPolynomial()
		{
			IntegerPolynomial i = F1.Multiply(F2.ToIntegerPolynomial());
			i.Add(F3.ToIntegerPolynomial());
			return i;
		}

		public IntegerPolynomial Multiply(IntegerPolynomial poly2, int modulus)
		{
			IntegerPolynomial c = Multiply(poly2);
			c.Mod(modulus);
			return c;
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + ((F1 == null) ? 0 : F1.GetHashCode());
			result = prime * result + ((F2 == null) ? 0 : F2.GetHashCode());
			result = prime * result + ((F3 == null) ? 0 : F3.GetHashCode());
			return result;
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (obj == null)
			{
				return false;
			}
			if (GetType() != obj.GetType())
			{
				return false;
			}
			ProductFormPolynomial other = (ProductFormPolynomial)obj;
			if (F1 == null)
			{
				if (other.F1 != null)
				{
					return false;
				}
			}
			else if (!F1.Equals(other.F1))
			{
				return false;
			}
			if (F2 == null)
			{
				if (other.F2 != null)
				{
					return false;
				}
			}
			else if (!F2.Equals(other.F2))
			{
				return false;
			}
			if (F3 == null)
			{
				if (other.F3 != null)
				{
					return false;
				}
			}
			else if (!F3.Equals(other.F3))
			{
				return false;
			}
			return true;
		}
	}
}