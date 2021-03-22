using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Pqc.Math.Ntru.Util;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /**
     * Represents a string of bits and supports appending, reading the head, and reading the tail.
     */
    public class BitString
    {
        byte[] bytes = new byte[4];
        int numBytes;   // includes the last byte even if only some of its bits are used
        int lastByteBits;   // lastByteBits <= 8

        /**
         * Appends all bits in a byte array to the end of the bit string.
         *
         * @param bytes a byte array
         */
        public void AppendBits(byte[] bytes)
        {
            foreach (byte b in bytes)
            {
                AppendBits(b);
            }
        }

        /**
         * Appends all bits in a byte to the end of the bit string.
         *
         * @param b a byte
         */

        private static byte[] CopyOf(byte[] src, int len)
        {
            byte[] tmp = new byte[len];

            for (int i = 0; i < src.Length; ++i)
            {
                tmp[i] = src[i];
            }

            return tmp;
        }

        public void AppendBits(byte b)
        {
            if (numBytes == bytes.Length)
            {
                bytes = CopyOf(bytes, 2 * bytes.Length);
            }

            if (numBytes == 0)
            {
                numBytes = 1;
                bytes[0] = b;
                lastByteBits = 8;
            }
            else if (lastByteBits == 8)
            {
                bytes[numBytes++] = b;
            }
            else
            {
                int s = 8 - lastByteBits;
                bytes[numBytes - 1] = (byte)(bytes[numBytes - 1] | ((byte) ((b & 0xFF) << lastByteBits)));
                bytes[numBytes++] = (byte)((b & 0xFF) >> s);
            }
        }

        /**
         * Returns the last <code>numBits</code> bits from the end of the bit string.
         *
         * @param numBits number of bits
         * @return a new <code>BitString</code> of length <code>numBits</code>
         */
        public BitString getTrailing(int numBits)
        {
            BitString newStr = new BitString();
            newStr.numBytes = (numBits + 7) / 8;
            newStr.bytes = new byte[newStr.numBytes];
            for (int i = 0; i < newStr.numBytes; i++)
            {
                newStr.bytes[i] = bytes[i];
            }

            newStr.lastByteBits = numBits % 8;
            if (newStr.lastByteBits == 0)
            {
                newStr.lastByteBits = 8;
            }
            else
            {
                int s = 32 - newStr.lastByteBits;
                newStr.bytes[newStr.numBytes - 1] = (byte)((newStr.bytes[newStr.numBytes - 1] << s).UnsignedRightShift(s));
            }

            return newStr;
        }

        /**
         * Returns up to 32 bits from the beginning of the bit string.
         *
         * @param numBits number of bits
         * @return an <code>int</code> whose lower <code>numBits</code> bits are the beginning of the bit string
         */
        public int getLeadingAsInt(int numBits)
        {
            int startBit = (numBytes - 1) * 8 + lastByteBits - numBits;
            int startByte = startBit / 8;

            int startBitInStartByte = startBit % 8;
            int sum = (bytes[startByte] & 0xFF).UnsignedRightShift(startBitInStartByte);
            int shift = 8 - startBitInStartByte;
            for (int i = startByte + 1; i < numBytes; i++)
            {
                sum |= (bytes[i] & 0xFF) << shift;
                shift += 8;
            }

            return sum;
        }

        public byte[] GetBytes()
        {
            return bytes.ToArray();
        }
    }
}
