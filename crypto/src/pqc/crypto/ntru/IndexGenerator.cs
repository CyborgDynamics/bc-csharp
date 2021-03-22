
using Org.BouncyCastle.Crypto;

using System.Linq;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /**
     * An implementation of the Index Generation Function in IEEE P1363.1.
     */
    public class IndexGenerator
    {
        private byte[] seed;
        private int N;
        private int c;
        private int minCallsR;
        private int totLen;
        private int remLen;
        private BitString buf;
        private int counter;
        private bool initialized;
        private IDigest hashAlg;
        private int hLen;

        /**
         * Constructs a new index generator.
         *
         * @param seed   a seed of arbitrary length to initialize the index generator with
         * @param params NtruEncrypt parameters
         */
        IndexGenerator(byte[] seed, NTRUEncryptionParameters encryptionParameters)
        {
            this.seed = seed;
            N = encryptionParameters.N;
            c = encryptionParameters.c;
            minCallsR = encryptionParameters.minCallsR;

            totLen = 0;
            remLen = 0;
            counter = 0;
            hashAlg = encryptionParameters.hashAlg;

            hLen = hashAlg.GetDigestSize();   // hash length
            initialized = false;
        }

        /*
         * Returns a number <code>i</code> such that <code>0 &lt;= i &lt; N</code>.
         */
        int nextIndex()
        {
            if (!initialized)
            {
                buf = new BitString();
                byte[] hash = new byte[hashAlg.GetDigestSize()];
                while (counter < minCallsR)
                {
                    AppendHash(buf, hash);
                    counter++;
                }
                totLen = minCallsR * 8 * hLen;
                remLen = totLen;
                initialized = true;
            }

            while (true)
            {
                totLen += c;
                BitString M = buf.getTrailing(remLen);
                if (remLen < c)
                {
                    int tmpLen = c - remLen;
                    int cThreshold = counter + (tmpLen + hLen - 1) / hLen;
                    byte[] hash = new byte[hashAlg.GetDigestSize()];
                    while (counter < cThreshold)
                    {
                        AppendHash(M, hash);
                        counter++;
                        if (tmpLen > 8 * hLen)
                        {
                            tmpLen -= 8 * hLen;
                        }
                    }
                    remLen = 8 * hLen - tmpLen;
                    buf = new BitString();
                    foreach (byte b in hash)
                    {
                        buf.AppendBits(b);
                    }
                }
                else
                {
                    remLen -= c;
                }

                int i = M.getLeadingAsInt(c);   // assume c<32
                if (i < (1 << c) - ((1 << c) % N))
                {
                    return i % N;
                }
            }
        }

        private void AppendHash(BitString m, byte[] hash)
        {
            hashAlg.BlockUpdate(seed, 0, seed.Length);

            putInt(hashAlg, counter);

            hashAlg.DoFinal(hash, 0);

            m.AppendBits(hash);
        }

        private void putInt(IDigest hashAlg, int counter)
        {
            hashAlg.Update((byte)(counter >> 24));
            hashAlg.Update((byte)(counter >> 16));
            hashAlg.Update((byte)(counter >> 8));
            hashAlg.Update((byte)counter);
        }

        private static byte[] CopyOf(byte[] src)
        {
            return src.ToArray();
        }
    }
}