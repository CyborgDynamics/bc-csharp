using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru { 
/**
 * A set of parameters for NtruEncrypt. Several predefined parameter sets are available and new ones can be created as well.
 */
public class NTRUEncryptionKeyGenerationParameters : KeyGenerationParameters
{
    /**
     * A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for key size.
     * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source (but the value present at class load time).
     */
    public static NTRUEncryptionKeyGenerationParameters EES1087EP2 = new NTRUEncryptionKeyGenerationParameters(1087, 2048, 120, 120, 256, 13, 25, 14, true, new byte[]{0, 6, 3}, true, false, new Sha512Digest());

    /**
     * A conservative (in terms of security) parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed.
     * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source (but the value present at class load time).
     */
    public static NTRUEncryptionKeyGenerationParameters EES1171EP1 = new NTRUEncryptionKeyGenerationParameters(1171, 2048, 106, 106, 256, 13, 20, 15, true, new byte[]{0, 6, 4}, true, false, new Sha512Digest());

    /**
     * A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for encryption/decryption speed.
     * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source (but the value present at class load time).
     */
    public static NTRUEncryptionKeyGenerationParameters EES1499EP1 = new NTRUEncryptionKeyGenerationParameters(1499, 2048, 79, 79, 256, 13, 17, 19, true, new byte[]{0, 6, 5}, true, false, new Sha512Digest());

    /**
     * A parameter set that gives 128 bits of security and uses simple ternary polynomials.
     * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source (but the value present at class load time).
     */
    public static NTRUEncryptionKeyGenerationParameters APR2011_439 = new NTRUEncryptionKeyGenerationParameters(439, 2048, 146, 130, 128, 9, 32, 9, true, new byte[]{0, 7, 101}, true, false, new Sha512Digest());

    /**
     * Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials and <code>f=1+pF</code>.
     * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source (but the value present at class load time).
     */
    public static NTRUEncryptionKeyGenerationParameters APR2011_439_FAST = new NTRUEncryptionKeyGenerationParameters(439, 2048, 9, 8, 5, 130, 128, 9, 32, 9, true, new byte[]{0, 7, 101}, true, true, new Sha512Digest());

    /**
     * A parameter set that gives 256 bits of security and uses simple ternary polynomials.
     * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source (but the value present at class load time).
     */
    public static NTRUEncryptionKeyGenerationParameters APR2011_743 = new NTRUEncryptionKeyGenerationParameters(743, 2048, 248, 220, 256, 10, 27, 14, true, new byte[]{0, 7, 105}, false, false, new Sha512Digest());

    /**
     * Like <code>APR2011_743</code>, this parameter set gives 256 bits of security but uses product-form polynomials and <code>f=1+pF</code>.
     * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source (but the value present at class load time).
     */
    public static NTRUEncryptionKeyGenerationParameters APR2011_743_FAST = new NTRUEncryptionKeyGenerationParameters(743, 2048, 11, 11, 15, 220, 256, 10, 27, 14, true, new byte[]{0, 7, 105}, false, true, new Sha512Digest());

    public int N, q, df, df1, df2, df3;
    public int dr;
    public int dr1;
    public int dr2;
    public int dr3;
    public int dg;
    int llen;
    public int maxMsgLenBytes;
    public int db;
    public int bufferLenBits;
    int bufferLenTrits;
    public int dm0;
    public int pkLen;
    public int c;
    public int minCallsR;
    public int minCallsMask;
    public bool hashSeed;
    public byte[] oid;
    public bool sparse;
    public bool fastFp;
    public int polyType;
    public IDigest hashAlg;

    /**
     * Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param df           number of ones in the private polynomial <code>f</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param db           number of random bits to prepend to the message
     * @param c            a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR    minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
     * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     * @param random       entropy source, if <code>null</code> uses {@link CryptoServicesRegistrar#getSecureRandom()}
     */
    public NTRUEncryptionKeyGenerationParameters(int N, int q, int df, int dm0, int db, int c, int minCallsR, int minCallsMask, bool hashSeed, byte[] oid, bool sparse, bool fastFp, IDigest hashAlg, SecureRandom random) : base(random ?? CryptoServicesRegistrar.GetSecureRandom(), db)
    {
        this.N = N;
        this.q = q;
        this.df = df;
        this.db = db;
        this.dm0 = dm0;
        this.c = c;
        this.minCallsR = minCallsR;
        this.minCallsMask = minCallsMask;
        this.hashSeed = hashSeed;
        this.oid = oid;
        this.sparse = sparse;
        this.fastFp = fastFp;
        this.polyType = (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE;
        this.hashAlg = hashAlg;
        Init();
    }

    /**
     * Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
     *
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param df           number of ones in the private polynomial <code>f</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param db           number of random bits to prepend to the message
     * @param c            a parameter for the Index Generation Function ({@link org.bouncycastle.pqc.crypto.ntru.IndexGenerator})
     * @param minCallsR    minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
     * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public NTRUEncryptionKeyGenerationParameters(int N, int q, int df, int dm0, int db, int c, int minCallsR, int minCallsMask, bool hashSeed, byte[] oid, bool sparse, bool fastFp, IDigest hashAlg) : this(N, q, df, dm0, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg, null)
    {       
    }

    /**
     * Constructs a parameter set that uses product-form private keys (i.e. <code>polyType=PRODUCT</code>).
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param df1          number of ones in the private polynomial <code>f1</code>
     * @param df2          number of ones in the private polynomial <code>f2</code>
     * @param df3          number of ones in the private polynomial <code>f3</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param db           number of random bits to prepend to the message
     * @param c            a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR    minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
     * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>
     * @param random       entropy source, if <code>null</code> uses {@link CryptoServicesRegistrar#getSecureRandom()}
     */
    public NTRUEncryptionKeyGenerationParameters(int N, int q, int df1, int df2, int df3, int dm0, int db, int c, int minCallsR, int minCallsMask, bool hashSeed, 
        byte[] oid, bool sparse, bool fastFp, IDigest hashAlg, SecureRandom random) : base(random != null ? random : CryptoServicesRegistrar.GetSecureRandom(), db)
    {
        this.N = N;
        this.q = q;
        this.df1 = df1;
        this.df2 = df2;
        this.df3 = df3;
        this.db = db;
        this.dm0 = dm0;
        this.c = c;
        this.minCallsR = minCallsR;
        this.minCallsMask = minCallsMask;
        this.hashSeed = hashSeed;
        this.oid = oid;
        this.sparse = sparse;
        this.fastFp = fastFp;
        this.polyType = (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT;
        this.hashAlg = hashAlg;
        Init();
    }

        /**
         * Constructs a parameter set that uses product-form private keys (i.e. <code>polyType=PRODUCT</code>).
         * Uses {@link CryptoServicesRegistrar#getSecureRandom()} as an entropy source.
         *
         * @param N            number of polynomial coefficients
         * @param q            modulus
         * @param df1          number of ones in the private polynomial <code>f1</code>
         * @param df2          number of ones in the private polynomial <code>f2</code>
         * @param df3          number of ones in the private polynomial <code>f3</code>
         * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
         * @param db           number of random bits to prepend to the message
         * @param c            a parameter for the Index Generation Function ({@link org.bouncycastle.pqc.crypto.ntru.IndexGenerator})
         * @param minCallsR    minimum number of hash calls for the IGF to make
         * @param minCallsMask minimum number of calls to generate the masking polynomial
         * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
         * @param oid          three bytes that uniquely identify the parameter set
         * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
         * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
         * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>
         */
        public NTRUEncryptionKeyGenerationParameters(int N, int q, int df1, int df2, int df3, int dm0, int db, int c, int minCallsR, int minCallsMask, bool hashSeed, byte[] oid, bool sparse, bool fastFp, IDigest hashAlg) :
            this(N, q, df1, df2, df3, dm0, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg, null)
        { }        

        private void Init()
    {
        dr = df;
        dr1 = df1;
        dr2 = df2;
        dr3 = df3;
        dg = N / 3;
        llen = 1;   // ceil(log2(maxMsgLenBytes))
        maxMsgLenBytes = N * 3 / 2 / 8 - llen - db / 8 - 1;
        bufferLenBits = (N * 3 / 2 + 7) / 8 * 8 + 1;
        bufferLenTrits = N - 1;
        pkLen = db;
    }

    /**
     * Reads a parameter set from an input stream.
     *
     * @param is an input stream
     * @throws java.io.IOException
     */
    public NTRUEncryptionKeyGenerationParameters(Stream inputStream) : base(CryptoServicesRegistrar.GetSecureRandom(), -1)
    {
        BinaryReader dis = new BinaryReader(inputStream);
        N = dis.ReadInt32();
        q = dis.ReadInt32();
        df = dis.ReadInt32();
        df1 = dis.ReadInt32();
        df2 = dis.ReadInt32();
        df3 = dis.ReadInt32();
        db = dis.ReadInt32();
        dm0 = dis.ReadInt32();
        c = dis.ReadInt32();
        minCallsR = dis.ReadInt32();
        minCallsMask = dis.ReadInt32();
        hashSeed = dis.ReadBoolean();
           oid = dis.ReadBytes(3);
        sparse = dis.ReadBoolean();
        fastFp = dis.ReadBoolean();
        polyType = dis.Read();

        string alg = dis.ReadString();

        if ("SHA-512".Equals(alg))
        {
            hashAlg = new Sha512Digest();
        }
        else if ("SHA-256".Equals(alg))
        {
            hashAlg = new Sha256Digest();
        }

        Init();
    }

    public NTRUEncryptionParameters GetEncryptionParameters()
    {
        if (polyType == (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
        {
            return new NTRUEncryptionParameters(N, q, df, dm0, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
        }
        else
        {
            return new NTRUEncryptionParameters(N, q, df1, df2, df3, dm0, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
        }
    }

    public NTRUEncryptionKeyGenerationParameters lone()
    {
        if (polyType == (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
        {
            return new NTRUEncryptionKeyGenerationParameters(N, q, df, dm0, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
        }
        else
        {
            return new NTRUEncryptionKeyGenerationParameters(N, q, df1, df2, df3, dm0, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
        }
    }

    /**
     * Returns the maximum length a plaintext message can be with this parameter set.
     *
     * @return the maximum length in bytes
     */
    public int GetMaxMessageLength()
    {
        return maxMsgLenBytes;
    }

    /**
     * Writes the parameter set to an output stream
     *
     * @param os an output stream
     * @throws java.io.IOException
     */
    public void WriteTo(Stream os)
    {
        BinaryWriter dos = new BinaryWriter(os);
        dos.Write(N);
        dos.Write(q);
        dos.Write(df);
        dos.Write(df1);
        dos.Write(df2);
        dos.Write(df3);
        dos.Write(db);
        dos.Write(dm0);
        dos.Write(c);
        dos.Write(minCallsR);
        dos.Write(minCallsMask);
        dos.Write(hashSeed);
        dos.Write(oid);
        dos.Write(sparse);
        dos.Write(fastFp);
        dos.Write(polyType);
        dos.Write(hashAlg.AlgorithmName);
    }


    public override int GetHashCode()
    {
        const int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result + bufferLenBits;
        result = prime * result + bufferLenTrits;
        result = prime * result + c;
        result = prime * result + db;
        result = prime * result + df;
        result = prime * result + df1;
        result = prime * result + df2;
        result = prime * result + df3;
        result = prime * result + dg;
        result = prime * result + dm0;
        result = prime * result + dr;
        result = prime * result + dr1;
        result = prime * result + dr2;
        result = prime * result + dr3;
        result = prime * result + (fastFp ? 1231 : 1237);
        result = prime * result + ((hashAlg == null) ? 0 : hashAlg.AlgorithmName.GetHashCode());
        result = prime * result + (hashSeed ? 1231 : 1237);
        result = prime * result + llen;
        result = prime * result + maxMsgLenBytes;
        result = prime * result + minCallsMask;
        result = prime * result + minCallsR;
        result = prime * result + oid.GetHashCode();
        result = prime * result + pkLen;
        result = prime * result + polyType;
        result = prime * result + q;
        result = prime * result + (sparse ? 1231 : 1237);
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
        NTRUEncryptionKeyGenerationParameters other = (NTRUEncryptionKeyGenerationParameters)obj;
        if (N != other.N)
        {
            return false;
        }
        if (bufferLenBits != other.bufferLenBits)
        {
            return false;
        }
        if (bufferLenTrits != other.bufferLenTrits)
        {
            return false;
        }
        if (c != other.c)
        {
            return false;
        }
        if (db != other.db)
        {
            return false;
        }
        if (df != other.df)
        {
            return false;
        }
        if (df1 != other.df1)
        {
            return false;
        }
        if (df2 != other.df2)
        {
            return false;
        }
        if (df3 != other.df3)
        {
            return false;
        }
        if (dg != other.dg)
        {
            return false;
        }
        if (dm0 != other.dm0)
        {
            return false;
        }
        if (dr != other.dr)
        {
            return false;
        }
        if (dr1 != other.dr1)
        {
            return false;
        }
        if (dr2 != other.dr2)
        {
            return false;
        }
        if (dr3 != other.dr3)
        {
            return false;
        }
        if (fastFp != other.fastFp)
        {
            return false;
        }
        if (hashAlg == null)
        {
            if (other.hashAlg != null)
            {
                return false;
            }
        }
        else if (!hashAlg.AlgorithmName.Equals(other.hashAlg.AlgorithmName))
        {
            return false;
        }
        if (hashSeed != other.hashSeed)
        {
            return false;
        }
        if (llen != other.llen)
        {
            return false;
        }
        if (maxMsgLenBytes != other.maxMsgLenBytes)
        {
            return false;
        }
        if (minCallsMask != other.minCallsMask)
        {
            return false;
        }
        if (minCallsR != other.minCallsR)
        {
            return false;
        }
        if (!oid.Equals(other.oid))
        {
            return false;
        }
        if (pkLen != other.pkLen)
        {
            return false;
        }
        if (polyType != other.polyType)
        {
            return false;
        }
        if (q != other.q)
        {
            return false;
        }
        if (sparse != other.sparse)
        {
            return false;
        }
        return true;
    }

    public override string ToString()
    {
        StringBuilder output = new StringBuilder("EncryptionParameters(N=" + N + " q=" + q);
        if (polyType == (int)NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
        {
            output.Append(" polyType=SIMPLE df=" + df);
        }
        else
        {
            output.Append(" polyType=PRODUCT df1=" + df1 + " df2=" + df2 + " df3=" + df3);
        }
        output.Append(" dm0=" + dm0 + " db=" + db + " c=" + c + " minCallsR=" + minCallsR + " minCallsMask=" + minCallsMask +
            " hashSeed=" + hashSeed + " hashAlg=" + hashAlg + " oid=" + BitConverter.ToString(oid) + " sparse=" + sparse + ")");
        return output.ToString();
    }
}
}