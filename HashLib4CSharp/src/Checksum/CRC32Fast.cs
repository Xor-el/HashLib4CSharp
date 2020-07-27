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
using System.Runtime.InteropServices;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Checksum
{
    internal abstract class CRC32Fast : Hash, IChecksum, IHash32, ITransformBlock
    {
        protected uint CurrentCrc;

        protected CRC32Fast()
            : base(4, 1)
        {
        }

        public override void Initialize() => CurrentCrc = 0;

        public override IHashResult TransformFinal()
        {
            var buffer = new byte[HashSize];
            Converters.ReadUInt32AsBytesBE(CurrentCrc, buffer, 0);
            var result = new HashResult(buffer);
            Initialize();

            return result;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private readonly struct Block
        {
            public readonly uint one;
            public readonly uint two;
            public readonly uint three;
            public readonly uint four;
        }

        protected void LocalCrcCompute(uint[][] crcTable, ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            const int unroll = 4;
            const int bytesAtOnce = 16 * unroll;

            var crc = ~CurrentCrc;
            var leftovers = BitConverter.IsLittleEndian ? ComputeLittleEndianBlocks(data, bytesAtOnce, ref crc, crcTable)
                                                        : ComputeBigEndianBlocks(data, bytesAtOnce, ref crc, crcTable);

            // remaining 1 to 63 bytes (standard algorithm)
            foreach (var b in leftovers)
                crc = (crc >> 8) ^ crcTable[0][(crc & 0xFF) ^ b];

            CurrentCrc = ~crc;
        }

        private static ReadOnlySpan<byte> ComputeBigEndianBlocks(ReadOnlySpan<byte> data, int bytesAtOnce, ref uint crc, uint[][] crcTable)
        {
            var dataSpan = data;
            var blockCount = data.Length / bytesAtOnce;
            var bytesScanned = blockCount * bytesAtOnce;
            var blocks = MemoryMarshal.Cast<byte, Block>(dataSpan.Slice(0, bytesScanned));
            foreach (var block in blocks)
            {
                var one = block.one ^ Bits.ReverseBytesUInt32(crc);

                crc = crcTable[0][block.four & 0xFF] ^ crcTable[1][(block.four >> 8) & 0xFF] ^ crcTable[2][(block.four >> 16) & 0xFF] ^ crcTable[3][(block.four >> 24) & 0xFF] ^ crcTable[4][block.three & 0xFF] ^ crcTable[5][(block.three >> 8) & 0xFF] ^ crcTable[6][(block.three >> 16) & 0xFF] ^ crcTable[7][(block.three >> 24) & 0xFF] ^ crcTable[8][block.two & 0xFF] ^ crcTable[9][(block.two >> 8) & 0xFF] ^ crcTable[10][(block.two >> 16) & 0xFF] ^ crcTable[11][(block.two >> 24) & 0xFF] ^ crcTable[12][one & 0xFF] ^ crcTable[13][(one >> 8) & 0xFF] ^ crcTable[14][(one >> 16) & 0xFF] ^ crcTable[15][(one >> 24) & 0xFF];
            }

            return dataSpan.Slice(bytesScanned);
        }

        private static ReadOnlySpan<byte> ComputeLittleEndianBlocks(ReadOnlySpan<byte> data, int bytesAtOnce, ref uint crc, uint[][] crcTable)
        {
            var dataSpan = data;
            var blockCount = data.Length / bytesAtOnce;
            var bytesScanned = blockCount * bytesAtOnce;
            var blocks = MemoryMarshal.Cast<byte, Block>(dataSpan.Slice(0, bytesScanned));
            foreach (var block in blocks)
            {
                var one = block.one ^ crc;

                crc = crcTable[0][(block.four >> 24) & 0xFF] ^ crcTable[1][(block.four >> 16) & 0xFF] ^ crcTable[2][(block.four >> 8) & 0xFF] ^ crcTable[3][block.four & 0xFF] ^ crcTable[4][(block.three >> 24) & 0xFF] ^ crcTable[5][(block.three >> 16) & 0xFF] ^ crcTable[6][(block.three >> 8) & 0xFF] ^ crcTable[7][block.three & 0xFF] ^ crcTable[8][(block.two >> 24) & 0xFF] ^ crcTable[9][(block.two >> 16) & 0xFF] ^ crcTable[10][(block.two >> 8) & 0xFF] ^ crcTable[11][block.two & 0xFF] ^ crcTable[12][(one >> 24) & 0xFF] ^ crcTable[13][(one >> 16) & 0xFF] ^ crcTable[14][(one >> 8) & 0xFF] ^ crcTable[15][one & 0xFF];
            }

            return dataSpan.Slice(bytesScanned);
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
                var temp = (uint)idx;

                for (var jdx = 0; jdx < 16; jdx++)
                {
                    var kdx = 0;
                    while (kdx < 8)
                    {
                        temp = (uint)((temp >> 1) ^ (-(int)(temp & 1) & polynomial));
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

        public override IHash Clone() => new Crc32PKZip { CurrentCrc = CurrentCrc, BufferSize = BufferSize };

        public override void TransformByteSpan(ReadOnlySpan<byte> data) =>
            LocalCrcCompute(Crc32PKZipTable, data);
    }

    internal sealed class Crc32Castagnoli : CRC32Fast
    {
        // Polynomial Reversed
        private const uint Crc32CastagnoliPolynomial = 0x82F63B78;

        private static readonly uint[][] Crc32CastagnoliTable;

        static Crc32Castagnoli() => Crc32CastagnoliTable = Init_CRC_Table(Crc32CastagnoliPolynomial);

        public override IHash Clone() => new Crc32Castagnoli { CurrentCrc = CurrentCrc, BufferSize = BufferSize };

        public override void TransformByteSpan(ReadOnlySpan<byte> data) =>
            LocalCrcCompute(Crc32CastagnoliTable, data);
    }
}