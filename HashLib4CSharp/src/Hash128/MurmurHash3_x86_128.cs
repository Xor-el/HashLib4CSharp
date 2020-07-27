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
    internal sealed class MurmurHash3_x86_128 : Hash, IHash128, IHashWithKey, ITransformBlock
    {
        private uint _key, _h1, _h2, _h3, _h4, _totalLength;
        private int _idx;
        private byte[] _buffer;

        private const uint CKey = 0x0;

        private const uint C1 = 0x239B961B;
        private const uint C2 = 0xAB0E9789;
        private const uint C3 = 0x38B34AE5;
        private const uint C4 = 0xA1E38B93;
        private const uint C5 = 0x85EBCA6B;
        private const uint C6 = 0xC2B2AE35;
        private const uint C7 = 0x561CCD1B;
        private const uint C8 = 0x0BCAA747;
        private const uint C9 = 0x96CD1C35;
        private const uint C10 = 0x32AC3B17;

        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        internal MurmurHash3_x86_128()
            : base(16, 16)
        {
            _key = CKey;
            _buffer = new byte[16];
        }

        public override IHash Clone() =>
            new MurmurHash3_x86_128
            {
                _key = _key,
                _h1 = _h1,
                _h2 = _h2,
                _h3 = _h3,
                _h4 = _h4,
                _totalLength = _totalLength,
                _idx = _idx,
                _buffer = ArrayUtils.Clone(_buffer),
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            _h1 = _key;
            _h2 = _key;
            _h3 = _key;
            _h4 = _key;

            _totalLength = 0;
            _idx = 0;
        }

        public override IHashResult TransformFinal()
        {
            Finish();
            var buffer = new byte[HashSize];

            Converters.ReadUInt32AsBytesBE(_h1, buffer, 0);
            Converters.ReadUInt32AsBytesBE(_h2, buffer, 4);
            Converters.ReadUInt32AsBytesBE(_h3, buffer, 8);
            Converters.ReadUInt32AsBytesBE(_h4, buffer, 12);

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
            _totalLength += (uint)len;

            fixed (byte* dataPtr = data)
            {
                //consume last pending bytes
                if (_idx != 0 && len != 0)
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
                var h3 = _h3;
                var h4 = _h4;
                var dataPtr2 = (uint*)(dataPtr + index);
                while (i < nBlocks)
                {
                    var block1 = Converters.ReadPCardinalAsUInt32LE(dataPtr2 + idx);
                    idx++;
                    var block2 = Converters.ReadPCardinalAsUInt32LE(dataPtr2 + idx);
                    idx++;
                    var block3 = Converters.ReadPCardinalAsUInt32LE(dataPtr2 + idx);
                    idx++;
                    var block4 = Converters.ReadPCardinalAsUInt32LE(dataPtr2 + idx);
                    idx++;

                    block1 *= C1;
                    block1 = Bits.RotateLeft32(block1, 15);
                    block1 *= C2;
                    h1 ^= block1;

                    h1 = Bits.RotateLeft32(h1, 19);

                    h1 += h2;
                    h1 = h1 * 5 + C7;

                    block2 *= C2;
                    block2 = Bits.RotateLeft32(block2, 16);
                    block2 *= C3;
                    h2 ^= block2;

                    h2 = Bits.RotateLeft32(h2, 17);

                    h2 += h3;
                    h2 = h2 * 5 + C8;

                    block3 *= C3;
                    block3 = Bits.RotateLeft32(block3, 17);
                    block3 *= C4;
                    h3 ^= block3;

                    h3 = Bits.RotateLeft32(h3, 15);

                    h3 += h4;
                    h3 = h3 * 5 + C9;

                    block4 *= C4;
                    block4 = Bits.RotateLeft32(block4, 18);
                    block4 *= C1;
                    h4 ^= block4;

                    h4 = Bits.RotateLeft32(h4, 13);

                    h4 += h1;
                    h4 = h4 * 5 + C10;

                    i++;
                }

                _h1 = h1;
                _h2 = h2;
                _h3 = h3;
                _h4 = h4;

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
                var block1 = Converters.ReadBytesAsUInt32LE(bufferPtr, 0);
                var block2 = Converters.ReadBytesAsUInt32LE(bufferPtr, 4);
                var block3 = Converters.ReadBytesAsUInt32LE(bufferPtr, 8);
                var block4 = Converters.ReadBytesAsUInt32LE(bufferPtr, 12);

                block1 *= C1;
                block1 = Bits.RotateLeft32(block1, 15);
                block1 *= C2;
                _h1 ^= block1;

                _h1 = Bits.RotateLeft32(_h1, 19);

                _h1 += _h2;
                _h1 = _h1 * 5 + C7;

                block2 *= C2;
                block2 = Bits.RotateLeft32(block2, 16);
                block2 *= C3;
                _h2 ^= block2;

                _h2 = Bits.RotateLeft32(_h2, 17);

                _h2 += _h3;
                _h2 = _h2 * 5 + C8;

                block3 *= C3;
                block3 = Bits.RotateLeft32(block3, 17);
                block3 *= C4;
                _h3 ^= block3;

                _h3 = Bits.RotateLeft32(_h3, 15);

                _h3 += _h4;
                _h3 = _h3 * 5 + C9;

                block4 *= C4;
                block4 = Bits.RotateLeft32(block4, 18);
                block4 *= C1;
                _h4 ^= block4;

                _h4 = Bits.RotateLeft32(_h4, 13);

                _h4 += _h1;
                _h4 = _h4 * 5 + C10;

                _idx = 0;
            }
        }

        private void Finish()
        {
            // tail
            uint k1 = 0;
            uint k2 = 0;
            uint k3 = 0;
            uint k4 = 0;

            var length = _idx;
            if (length != 0)
            {
                switch (length)
                {
                    case 15:
                        k4 ^= (uint)(_buffer[14] << 16);
                        k4 ^= (uint)(_buffer[13] << 8);
                        k4 ^= (uint)(_buffer[12] << 0);

                        k4 *= C4;
                        k4 = Bits.RotateLeft32(k4, 18);
                        k4 *= C1;
                        _h4 ^= k4;
                        break;

                    case 14:
                        k4 ^= (uint)(_buffer[13] << 8);
                        k4 ^= (uint)(_buffer[12] << 0);
                        k4 *= C4;
                        k4 = Bits.RotateLeft32(k4, 18);
                        k4 *= C1;
                        _h4 ^= k4;
                        break;

                    case 13:
                        k4 ^= (uint)(_buffer[12] << 0);
                        k4 *= C4;
                        k4 = Bits.RotateLeft32(k4, 18);
                        k4 *= C1;
                        _h4 ^= k4;
                        break;
                }

                if (length > 12)
                    length = 12;

                switch (length)
                {
                    case 12:
                        k3 ^= (uint)(_buffer[11] << 24);
                        k3 ^= (uint)(_buffer[10] << 16);
                        k3 ^= (uint)(_buffer[9] << 8);
                        k3 ^= (uint)(_buffer[8] << 0);

                        k3 *= C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 *= C4;
                        _h3 ^= k3;
                        break;

                    case 11:
                        k3 ^= (uint)(_buffer[10] << 16);
                        k3 ^= (uint)(_buffer[9] << 8);
                        k3 ^= (uint)(_buffer[8] << 0);

                        k3 *= C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 *= C4;
                        _h3 ^= k3;
                        break;

                    case 10:
                        k3 ^= (uint)(_buffer[9] << 8);
                        k3 ^= (uint)(_buffer[8] << 0);

                        k3 *= C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 *= C4;
                        _h3 ^= k3;
                        break;

                    case 9:
                        k3 ^= (uint)(_buffer[8] << 0);

                        k3 *= C3;
                        k3 = Bits.RotateLeft32(k3, 17);
                        k3 *= C4;
                        _h3 ^= k3;
                        break;
                }

                if (length > 8)
                    length = 8;

                switch (length)
                {
                    case 8:
                        k2 ^= (uint)(_buffer[7] << 24);
                        k2 ^= (uint)(_buffer[6] << 16);
                        k2 ^= (uint)(_buffer[5] << 8);
                        k2 ^= (uint)(_buffer[4] << 0);

                        k2 *= C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 *= C3;
                        _h2 ^= k2;
                        break;

                    case 7:
                        k2 ^= (uint)(_buffer[6] << 16);
                        k2 ^= (uint)(_buffer[5] << 8);
                        k2 ^= (uint)(_buffer[4] << 0);

                        k2 *= C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 *= C3;
                        _h2 ^= k2;
                        break;

                    case 6:
                        k2 ^= (uint)(_buffer[5] << 8);
                        k2 ^= (uint)(_buffer[4] << 0);

                        k2 *= C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 *= C3;
                        _h2 ^= k2;
                        break;

                    case 5:
                        k2 ^= (uint)(_buffer[4] << 0);

                        k2 *= C2;
                        k2 = Bits.RotateLeft32(k2, 16);
                        k2 *= C3;
                        _h2 ^= k2;
                        break;
                }

                if (length > 4)
                    length = 4;

                switch (length)
                {
                    case 4:
                        k1 ^= (uint)(_buffer[3] << 24);
                        k1 ^= (uint)(_buffer[2] << 16);
                        k1 ^= (uint)(_buffer[1] << 8);
                        k1 ^= (uint)(_buffer[0] << 0);

                        k1 *= C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 3:
                        k1 ^= (uint)(_buffer[2] << 16);
                        k1 ^= (uint)(_buffer[1] << 8);
                        k1 ^= (uint)(_buffer[0] << 0);

                        k1 *= C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 2:
                        k1 ^= (uint)(_buffer[1] << 8);
                        k1 ^= (uint)(_buffer[0] << 0);

                        k1 *= C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;

                    case 1:
                        k1 ^= (uint)(_buffer[0] << 0);

                        k1 *= C1;
                        k1 = Bits.RotateLeft32(k1, 15);
                        k1 *= C2;
                        _h1 ^= k1;
                        break;
                }
            }

            // finalization

            _h1 ^= _totalLength;
            _h2 ^= _totalLength;
            _h3 ^= _totalLength;
            _h4 ^= _totalLength;

            _h1 += _h2;
            _h1 += _h3;
            _h1 += _h4;
            _h2 += _h1;
            _h3 += _h1;
            _h4 += _h1;

            _h1 ^= _h1 >> 16;
            _h1 *= C5;
            _h1 ^= _h1 >> 13;
            _h1 *= C6;
            _h1 ^= _h1 >> 16;

            _h2 ^= _h2 >> 16;
            _h2 *= C5;
            _h2 ^= _h2 >> 13;
            _h2 *= C6;
            _h2 ^= _h2 >> 16;

            _h3 ^= _h3 >> 16;
            _h3 *= C5;
            _h3 ^= _h3 >> 13;
            _h3 *= C6;
            _h3 ^= _h3 >> 16;

            _h4 ^= _h4 >> 16;
            _h4 *= C5;
            _h4 ^= _h4 >> 13;
            _h4 *= C6;
            _h4 ^= _h4 >> 16;

            _h1 += _h2;
            _h1 += _h3;
            _h1 += _h4;
            _h2 += _h1;
            _h3 += _h1;
            _h4 += _h1;
        }
    }
}