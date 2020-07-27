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

namespace HashLib4CSharp.Hash128
{
    internal sealed class MurmurHash3_x64_128 : Hash, IHash128, IHashWithKey, ITransformBlock
    {
        private ulong _h1, _h2, _totalLength;
        private uint _key;
        private int _idx;
        private byte[] _buffer;

        private const uint CKey = 0x0;

        private const ulong C1 = 0x87C37B91114253D5;
        private const ulong C2 = 0x4CF5AD432745937F;
        private const uint C3 = 0x52DCE729;
        private const uint C4 = 0x38495AB5;
        private const ulong C5 = 0xFF51AFD7ED558CCD;
        private const ulong C6 = 0xC4CEB9FE1A85EC53;


        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        internal MurmurHash3_x64_128()
            : base(16, 16)
        {
            _key = CKey;
            _buffer = new byte[16];
        }

        public override IHash Clone() =>
            new MurmurHash3_x64_128
            {
                _h1 = _h1,
                _h2 = _h2,
                _totalLength = _totalLength,
                _key = _key,
                _idx = _idx,
                _buffer = ArrayUtils.Clone(_buffer),
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            _h1 = _key;
            _h2 = _key;

            _totalLength = 0;
            _idx = 0;
        }

        public override IHashResult TransformFinal()
        {
            Finish();
            var buffer = new byte[HashSize];

            Converters.ReadUInt64AsBytesBE(_h1, buffer, 0);
            Converters.ReadUInt64AsBytesBE(_h2, buffer, 8);

            var result = new HashResult(buffer);
            Initialize();
            return result;
        }

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var length = data.Length;
            var index = 0;
            var len = length;
            var i = index;
            var idx = 0;
            _totalLength += (ulong)len;

            fixed (byte* dataPtr = data)
            {
                //consume last pending bytes
                if (_idx != 0 && length != 0)
                {
                    while (_idx < 16 && len != 0)
                    {
                        _buffer[_idx++] = *(dataPtr + index);
                        index++;
                        len--;
                    }

                    if (_idx == 16)
                        ProcessPending();
                }
                else
                    i = 0;

                var nBlocks = len >> 4;

                // body
                var h1 = _h1;
                var h2 = _h2;
                var dataPtr2 = (ulong*)(dataPtr + index);
                while (i < nBlocks)
                {
                    var block1 = Converters.ReadPUInt64AsUInt64LE(dataPtr2 + idx);
                    idx++;

                    var block2 = Converters.ReadPUInt64AsUInt64LE(dataPtr2 + idx);
                    idx++;

                    block1 *= C1;
                    block1 = Bits.RotateLeft64(block1, 31);
                    block1 *= C2;
                    h1 ^= block1;

                    h1 = Bits.RotateLeft64(h1, 27);
                    h1 += h2;
                    h1 = h1 * 5 + C3;

                    block2 *= C2;
                    block2 = Bits.RotateLeft64(block2, 33);
                    block2 *= C1;
                    h2 ^= block2;

                    h2 = Bits.RotateLeft64(h2, 31);
                    h2 += h1;
                    h2 = h2 * 5 + C4;

                    i++;
                }

                _h1 = h1;
                _h2 = h2;

                var offset = index + i * 16;
                while (offset < index + len)
                {
                    ByteUpdate(data[offset]);
                    offset++;
                }
            }
        }

        public int KeyLength => 4;

        public unsafe byte[] Key
        {
            get => Converters.ReadUInt32AsBytesLE(_key);
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                if (value.Length == 0)
                    _key = CKey;
                else
                {
                    if (value.Length != KeyLength)
                        throw new ArgumentException(string.Format(InvalidKeyLength, KeyLength));

                    fixed (byte* valuePtr = value)
                    {
                        _key = Converters.ReadBytesAsUInt32LE(valuePtr, 0);
                    }
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ByteUpdate(byte value)
        {
            _buffer[_idx++] = value;
            ProcessPending();
        }

        private unsafe void ProcessPending()
        {
            fixed (byte* bufferPtr = _buffer)
            {
                if (_idx < 16) return;
                var block1 = Converters.ReadBytesAsUInt64LE(bufferPtr, 0);
                var block2 = Converters.ReadBytesAsUInt64LE(bufferPtr, 8);

                block1 *= C1;
                block1 = Bits.RotateLeft64(block1, 31);
                block1 *= C2;
                _h1 ^= block1;

                _h1 = Bits.RotateLeft64(_h1, 27);
                _h1 += _h2;
                _h1 = _h1 * 5 + C3;

                block2 *= C2;
                block2 = Bits.RotateLeft64(block2, 33);
                block2 *= C1;
                _h2 ^= block2;

                _h2 = Bits.RotateLeft64(_h2, 31);
                _h2 += _h1;
                _h2 = _h2 * 5 + C4;

                _idx = 0;
            }
        }

        private void Finish()
        {
            // tail
            ulong k1 = 0;
            ulong k2 = 0;

            var length = _idx;
            if (length != 0)
            {
                switch (length)
                {
                    case 15:
                        k2 ^= (ulong)_buffer[14] << 48;
                        k2 ^= (ulong)_buffer[13] << 40;
                        k2 ^= (ulong)_buffer[12] << 32;
                        k2 ^= (ulong)_buffer[11] << 24;
                        k2 ^= (ulong)_buffer[10] << 16;
                        k2 ^= (ulong)_buffer[9] << 8;
                        k2 ^= (ulong)_buffer[8] << 0;
                        k2 *= C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 *= C1;
                        _h2 ^= k2;
                        break;

                    case 14:
                        k2 ^= (ulong)_buffer[13] << 40;
                        k2 ^= (ulong)_buffer[12] << 32;
                        k2 ^= (ulong)_buffer[11] << 24;
                        k2 ^= (ulong)_buffer[10] << 16;
                        k2 ^= (ulong)_buffer[9] << 8;
                        k2 ^= (ulong)_buffer[8] << 0;
                        k2 *= C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 *= C1;
                        _h2 ^= k2;
                        break;

                    case 13:
                        k2 ^= (ulong)_buffer[12] << 32;
                        k2 ^= (ulong)_buffer[11] << 24;
                        k2 ^= (ulong)_buffer[10] << 16;
                        k2 ^= (ulong)_buffer[9] << 8;
                        k2 ^= (ulong)_buffer[8] << 0;
                        k2 *= C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 *= C1;
                        _h2 ^= k2;
                        break;

                    case 12:
                        k2 ^= (ulong)_buffer[11] << 24;
                        k2 ^= (ulong)_buffer[10] << 16;
                        k2 ^= (ulong)_buffer[9] << 8;
                        k2 ^= (ulong)_buffer[8] << 0;
                        k2 *= C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 *= C1;
                        _h2 ^= k2;
                        break;

                    case 11:
                        k2 ^= (ulong)_buffer[10] << 16;
                        k2 ^= (ulong)_buffer[9] << 8;
                        k2 ^= (ulong)_buffer[8] << 0;
                        k2 *= C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 *= C1;
                        _h2 ^= k2;
                        break;

                    case 10:
                        k2 ^= (ulong)_buffer[9] << 8;
                        k2 ^= (ulong)_buffer[8] << 0;
                        k2 *= C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 *= C1;
                        _h2 ^= k2;
                        break;

                    case 9:
                        k2 ^= (ulong)_buffer[8] << 0;
                        k2 *= C2;
                        k2 = Bits.RotateLeft64(k2, 33);
                        k2 *= C1;
                        _h2 ^= k2;
                        break;
                }

                if (length > 8)
                    length = 8;

                switch (length)
                {
                    case 8:
                        k1 ^= (ulong)_buffer[7] << 56;
                        k1 ^= (ulong)_buffer[6] << 48;
                        k1 ^= (ulong)_buffer[5] << 40;
                        k1 ^= (ulong)_buffer[4] << 32;
                        k1 ^= (ulong)_buffer[3] << 24;
                        k1 ^= (ulong)_buffer[2] << 16;
                        k1 ^= (ulong)_buffer[1] << 8;
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 7:
                        k1 ^= (ulong)_buffer[6] << 48;
                        k1 ^= (ulong)_buffer[5] << 40;
                        k1 ^= (ulong)_buffer[4] << 32;
                        k1 ^= (ulong)_buffer[3] << 24;
                        k1 ^= (ulong)_buffer[2] << 16;
                        k1 ^= (ulong)_buffer[1] << 8;
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 6:
                        k1 ^= (ulong)_buffer[5] << 40;
                        k1 ^= (ulong)_buffer[4] << 32;
                        k1 ^= (ulong)_buffer[3] << 24;
                        k1 ^= (ulong)_buffer[2] << 16;
                        k1 ^= (ulong)_buffer[1] << 8;
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 5:
                        k1 ^= (ulong)_buffer[4] << 32;
                        k1 ^= (ulong)_buffer[3] << 24;
                        k1 ^= (ulong)_buffer[2] << 16;
                        k1 ^= (ulong)_buffer[1] << 8;
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 4:
                        k1 ^= (ulong)_buffer[3] << 24;
                        k1 ^= (ulong)_buffer[2] << 16;
                        k1 ^= (ulong)_buffer[1] << 8;
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 3:
                        k1 ^= (ulong)_buffer[2] << 16;
                        k1 ^= (ulong)_buffer[1] << 8;
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 2:
                        k1 ^= (ulong)_buffer[1] << 8;
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 1:
                        k1 ^= (ulong)_buffer[0] << 0;
                        k1 *= C1;
                        k1 = Bits.RotateLeft64(k1, 31);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;
                }
            }

            // finalization

            _h1 ^= _totalLength;
            _h2 ^= _totalLength;

            _h1 += _h2;
            _h2 += _h1;

            _h1 ^= _h1 >> 33;
            _h1 *= C5;
            _h1 ^= _h1 >> 33;
            _h1 *= C6;
            _h1 ^= _h1 >> 33;

            _h2 ^= _h2 >> 33;
            _h2 *= C5;
            _h2 ^= _h2 >> 33;
            _h2 *= C6;
            _h2 ^= _h2 >> 33;

            _h1 += _h2;
            _h2 += _h1;
        }
    }
}