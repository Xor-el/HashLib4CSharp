/*
HashLib4CSharp Library
Copyright (c) 2020 Ugochukwu Mmaduekwe
GitHub Profile URL <https://github.com/Xor-el>

Distributed under the MIT software license, see the accompanying LICENSE file
or visit http://www.opensource.org/licenses/mit-license.php.

Acknowledgements:
This library was sponsored by Sphere 10 Software (https://www.sphere10.com)
for the purposes of supporting the XXX (https://YYY) project.
*/

using System;
using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Checksum
{
    internal abstract class CRC32Fast : Hash, IChecksum, IHash32, ITransformBlock
    {
        protected uint CurrentCRC;

        protected CRC32Fast()
            : base(4, 1)
        {
        }

        public override void Initialize() => CurrentCRC = 0;

        public override IHashResult TransformFinal()
        {
            var buffer = new byte[HashSize];
            Converters.ReadUInt32AsBytesBE(CurrentCRC, buffer, 0);
            var result = new HashResult(buffer);
            Initialize();

            return result;
        }

        protected unsafe void LocalCrcCompute(uint[][] crcTable, byte[] data, int index,
            int length)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            Debug.Assert(index >= 0);
            Debug.Assert(length >= 0);
            Debug.Assert(index + length <= data.Length);

            const int unroll = 4;
            const int bytesAtOnce = 16 * unroll;
            var crc = ~CurrentCRC;

            if (BitConverter.IsLittleEndian)
                ComputeLittleEndianBlocks();
            else
                ComputeBigEndianBlocks();

            CurrentCRC = ~crc;

            void ComputeLittleEndianBlocks()
            {
                fixed (byte* dataPtr = data)
                {
                    var srcPtr = (uint*)(dataPtr + index);
                    while (length >= bytesAtOnce)
                    {
                        var unrolling = 0;
                        while (unrolling < unroll)
                        {
                            var one = Converters.ReadPCardinalAsUInt32(srcPtr) ^ crc;
                            srcPtr++;
                            var two = Converters.ReadPCardinalAsUInt32(srcPtr);
                            srcPtr++;
                            var three = Converters.ReadPCardinalAsUInt32(srcPtr);
                            srcPtr++;
                            var four = Converters.ReadPCardinalAsUInt32(srcPtr);
                            srcPtr++;

                            crc = crcTable[0][(four >> 24) & 0xFF] ^ crcTable[1]
                                        [(four >> 16) & 0xFF] ^ crcTable[2][(four >> 8) & 0xFF]
                                    ^ crcTable[3][four & 0xFF] ^ crcTable[4]
                                        [(three >> 24) & 0xFF] ^ crcTable[5][(three >> 16) & 0xFF]
                                    ^ crcTable[6][(three >> 8) & 0xFF] ^ crcTable[7]
                                        [three & 0xFF] ^ crcTable[8][(two >> 24) & 0xFF] ^ crcTable
                                        [9][(two >> 16) & 0xFF] ^ crcTable[10][(two >> 8) & 0xFF]
                                    ^ crcTable[11][two & 0xFF] ^ crcTable[12][(one >> 24) & 0xFF]
                                    ^ crcTable[13][(one >> 16) & 0xFF] ^ crcTable[14]
                                        [(one >> 8) & 0xFF] ^ crcTable[15][one & 0xFF];

                            unrolling++;
                        }

                        length -= bytesAtOnce;
                    }

                    var srcPtr2 = (byte*)srcPtr;
                    // remaining 1 to 63 bytes (standard algorithm)
                    while (length != 0)
                    {
                        crc = (crc >> 8) ^ crcTable[0][(crc & 0xFF) ^ *srcPtr2];
                        srcPtr2++;
                        length--;
                    }
                }
            }


            void ComputeBigEndianBlocks()
            {
                fixed (byte* dataPtr = data)
                {
                    var srcPtr = (uint*)(dataPtr + index);
                    while (length >= bytesAtOnce)
                    {
                        var unrolling = 0;
                        while (unrolling < unroll)
                        {
                            var one = Converters.ReadPCardinalAsUInt32(srcPtr) ^ Bits.ReverseBytesUInt32(crc);
                            srcPtr++;
                            var two = Converters.ReadPCardinalAsUInt32(srcPtr);
                            srcPtr++;
                            var three = Converters.ReadPCardinalAsUInt32(srcPtr);
                            srcPtr++;
                            var four = Converters.ReadPCardinalAsUInt32(srcPtr);
                            srcPtr++;

                            crc = crcTable[0][four & 0xFF] ^ crcTable[1]
                                        [(four >> 8) & 0xFF] ^ crcTable[2][(four >> 16) & 0xFF]
                                    ^ crcTable[3][(four >> 24) & 0xFF] ^ crcTable[4]
                                        [three & 0xFF] ^ crcTable[5][(three >> 8) & 0xFF] ^ crcTable
                                        [6][(three >> 16) & 0xFF] ^ crcTable[7][(three >> 24) & 0xFF]
                                    ^ crcTable[8][two & 0xFF] ^ crcTable[9][(two >> 8) & 0xFF]
                                    ^ crcTable[10][(two >> 16) & 0xFF] ^ crcTable[11]
                                        [(two >> 24) & 0xFF] ^ crcTable[12][one & 0xFF] ^ crcTable
                                        [13][(one >> 8) & 0xFF] ^ crcTable[14][(one >> 16) & 0xFF]
                                    ^ crcTable[15][(one >> 24) & 0xFF];

                            unrolling++;
                        }

                        length -= bytesAtOnce;
                    }

                    var srcPtr2 = (byte*)srcPtr;
                    // remaining 1 to 63 bytes (standard algorithm)
                    while (length != 0)
                    {
                        crc = (crc >> 8) ^ crcTable[0][(crc & 0xFF) ^ *srcPtr2];
                        srcPtr2++;
                        length--;
                    }
                }
            }
        }

        protected static uint[][] Init_CRC_Table(uint polynomial)
        {
            var result = new uint[16][];
            for (var i = 0; i < result.Length; i++)
            {
                result[i] = new uint[256];
            }

            for (var idx = 0; idx < 256; idx++)
            {
                var temp = (uint) idx;

                for (var jdx = 0; jdx < 16; jdx++)
                {
                    var kdx = 0;
                    while (kdx < 8)
                    {
                        temp = (uint) ((temp >> 1) ^ (-(int) (temp & 1) & polynomial));
                        result[jdx][idx] = temp;
                        kdx++;
                    }
                }
            }

            return result;
        }
    }

    internal sealed class Crc32PKZip : CRC32Fast
    {
        // Polynomial Reversed
        private const uint Crc32PKZipPolynomial = 0xEDB88320;

        private static readonly uint[][] Crc32PKZipTable;

        static Crc32PKZip() => Crc32PKZipTable = Init_CRC_Table(Crc32PKZipPolynomial);

        public override IHash Clone() => new Crc32PKZip {CurrentCRC = CurrentCRC, BufferSize = BufferSize};

        public override void TransformBytes(byte[] data, int index, int length) =>
            LocalCrcCompute(Crc32PKZipTable, data, index, length);
    }

    internal sealed class Crc32Castagnoli : CRC32Fast
    {
        // Polynomial Reversed
        private const uint Crc32CastagnoliPolynomial = 0x82F63B78;

        private static readonly uint[][] Crc32CastagnoliTable;

        static Crc32Castagnoli() => Crc32CastagnoliTable = Init_CRC_Table(Crc32CastagnoliPolynomial);

        public override IHash Clone() => new Crc32Castagnoli {CurrentCRC = CurrentCRC, BufferSize = BufferSize};

        public override void TransformBytes(byte[] data, int index, int length) =>
            LocalCrcCompute(Crc32CastagnoliTable, data, index, length);
    }
}