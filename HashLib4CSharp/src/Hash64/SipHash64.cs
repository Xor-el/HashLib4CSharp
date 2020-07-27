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
using System.Runtime.CompilerServices;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash64
{
    internal abstract class SipHash : Hash, IHash64, IHashWithKey, ITransformBlock
    {
        protected ulong V00, V01, V02, V03, Key00, Key01, TotalLength;
        protected int CompressionRounds, FinalizationRounds, Idx;
        protected byte[] Buffer;

        private const ulong V0 = 0x736F6D6570736575;
        private const ulong V1 = 0x646F72616E646F6D;
        private const ulong V2 = 0x6C7967656E657261;
        private const ulong V3 = 0x7465646279746573;
        private const ulong Key0 = 0x0706050403020100;
        private const ulong Key1 = 0x0F0E0D0C0B0A0908;

        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        protected SipHash(int hashSize, int blockSize)
            : base(hashSize, blockSize)
        {
            Key00 = Key0;
            Key01 = Key1;
            Buffer = new byte[8];
        }

        public override void Initialize()
        {
            V00 = V0;
            V01 = V1;
            V02 = V2;
            V03 = V3;
            TotalLength = 0;
            Idx = 0;

            V03 ^= Key01;
            V02 ^= Key00;
            V01 ^= Key01;
            V00 ^= Key00;
        }

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var length = data.Length;
            var index = 0;
            var len = length;
            var idx = index;

            TotalLength += (uint) len;

            fixed (byte* dataPtr = data)
            {
                // consume last pending bytes
                ulong block;
                if (Idx != 0 && length != 0)
                {
                    while (Idx < 8 && len != 0)
                    {
                        Buffer[Idx] = *(dataPtr + index);
                        Idx++;
                        index++;
                        len--;
                    }

                    if (Idx == 8)
                    {
                        fixed (byte* bufferPtr = Buffer)
                        {
                            block = Converters.ReadBytesAsUInt64LE(bufferPtr, 0);
                            ProcessBlock(block);
                            Idx = 0;
                        }
                    }
                }
                else
                {
                    idx = 0;
                }

                var nBlocks = len >> 3;

                // body
                var dataPtr2 = (ulong*) (dataPtr + index);
                while (idx < nBlocks)
                {
                    block = Converters.ReadPUInt64AsUInt64LE(dataPtr2 + idx);
                    ProcessBlock(block);
                    idx++;
                }

                // save pending end bytes
                var offset = index + idx * 8;

                while (offset < len + index)
                {
                    ByteUpdate(data[offset]);
                    offset++;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Compress()
        {
            V00 += V01;
            V02 += V03;
            V01 = Bits.RotateLeft64(V01, 13);
            V03 = Bits.RotateLeft64(V03, 16);
            V01 ^= V00;
            V03 ^= V02;
            V00 = Bits.RotateLeft64(V00, 32);
            V02 += V01;
            V00 += V03;
            V01 = Bits.RotateLeft64(V01, 17);
            V03 = Bits.RotateLeft64(V03, 21);
            V01 ^= V02;
            V03 ^= V00;
            V02 = Bits.RotateLeft64(V02, 32);
        }

        protected void CompressTimes(int times)
        {
            var i = 0;
            while (i < times)
            {
                Compress();
                i++;
            }
        }

        protected abstract byte GetMagicXor();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessBlock(ulong block)
        {
            V03 ^= block;
            CompressTimes(CompressionRounds);
            V00 ^= block;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void ByteUpdate(byte value)
        {
            Buffer[Idx] = value;
            Idx++;
            if (Idx < 8) return;
            fixed (byte* bufferPtr = Buffer)
            {
                var block = Converters.ReadBytesAsUInt64LE(bufferPtr, 0);
                ProcessBlock(block);
                Idx = 0;
            }
        }

        protected ulong ProcessFinalBlock()
        {
            var result = (TotalLength & 0xFF) << 56;

            if (Idx == 0) return result;
            switch (Idx)
            {
                case 7:
                    result |= (ulong) Buffer[6] << 48;
                    result |= (ulong) Buffer[5] << 40;
                    result |= (ulong) Buffer[4] << 32;
                    result |= (ulong) Buffer[3] << 24;
                    result |= (ulong) Buffer[2] << 16;
                    result |= (ulong) Buffer[1] << 8;
                    result |= Buffer[0];
                    break;

                case 6:
                    result |= (ulong) Buffer[5] << 40;
                    result |= (ulong) Buffer[4] << 32;
                    result |= (ulong) Buffer[3] << 24;
                    result |= (ulong) Buffer[2] << 16;
                    result |= (ulong) Buffer[1] << 8;
                    result |= Buffer[0];
                    break;

                case 5:
                    result |= (ulong) Buffer[4] << 32;
                    result |= (ulong) Buffer[3] << 24;
                    result |= (ulong) Buffer[2] << 16;
                    result |= (ulong) Buffer[1] << 8;
                    result |= Buffer[0];
                    break;

                case 4:
                    result |= (ulong) Buffer[3] << 24;
                    result |= (ulong) Buffer[2] << 16;
                    result |= (ulong) Buffer[1] << 8;
                    result |= Buffer[0];
                    break;

                case 3:
                    result |= (ulong) Buffer[2] << 16;
                    result |= (ulong) Buffer[1] << 8;
                    result |= Buffer[0];
                    break;

                case 2:
                    result |= (ulong) Buffer[1] << 8;
                    result |= Buffer[0];
                    break;

                case 1:
                    result |= Buffer[0];
                    break;
            }

            return result;
        }

        public virtual int KeyLength => 16;

        public virtual unsafe byte[] Key
        {
            get
            {
                var key = new byte[KeyLength];
                Converters.ReadUInt64AsBytesLE(Key00, key, 0);
                Converters.ReadUInt64AsBytesLE(Key01, key, 8);
                return key;
            }
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                if (value.Length == 0)
                {
                    Key00 = Key0;
                    Key01 = Key1;
                }
                else
                {
                    if (value.Length != KeyLength)
                        throw new ArgumentException(string.Format(InvalidKeyLength, KeyLength));

                    fixed (byte* valuePtr = value)
                    {
                        Key00 = Converters.ReadBytesAsUInt64LE(valuePtr, 0);
                        Key01 = Converters.ReadBytesAsUInt64LE(valuePtr, 8);
                    }
                }
            }
        }
    }

    internal abstract class SipHash64 : SipHash
    {
        protected SipHash64(int compressionRounds, int finalizationRounds) : base(8, 8)
        {
            CompressionRounds = compressionRounds;
            FinalizationRounds = finalizationRounds;
        }

        protected override byte GetMagicXor() => 0xFF;

        public override IHashResult TransformFinal()
        {
            var finalBlock = ProcessFinalBlock();
            V03 ^= finalBlock;
            CompressTimes(CompressionRounds);
            V00 ^= finalBlock;
            V02 ^= GetMagicXor();
            CompressTimes(FinalizationRounds);
            var buffer = new byte[HashSize];
            Converters.ReadUInt64AsBytesLE(V00 ^ V01 ^ V02 ^ V03, buffer, 0);
            var result = new HashResult(buffer);
            Initialize();
            return result;
        }
    }

    internal sealed class SipHash64_2_4 : SipHash64
    {
        internal SipHash64_2_4() : base(2, 4)
        {
        }

        public override IHash Clone() =>
            new SipHash64_2_4
            {
                V00 = V00,
                V01 = V01,
                V02 = V02,
                V03 = V03,
                Key00 = Key00,
                Key01 = Key01,
                TotalLength = TotalLength,
                CompressionRounds = CompressionRounds,
                FinalizationRounds = FinalizationRounds,
                Idx = Idx,
                Buffer = ArrayUtils.Clone(Buffer),
                BufferSize = BufferSize
            };
    }
}