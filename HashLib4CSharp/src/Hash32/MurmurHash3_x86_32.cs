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

namespace HashLib4CSharp.Hash32
{
    internal sealed class MurmurHash3_x86_32 : Hash, IHash32, IHashWithKey, ITransformBlock
    {
        private uint _key, _h, _totalLength;
        private int _idx;
        private byte[] _buffer;

        private const uint CKey = 0x0;

        private const uint C1 = 0xCC9E2D51;
        private const uint C2 = 0x1B873593;
        private const uint C3 = 0xE6546B64;
        private const uint C4 = 0x85EBCA6B;
        private const uint C5 = 0xC2B2AE35;

        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        internal MurmurHash3_x86_32()
            : base(4, 4)
        {
            _key = CKey;
            _buffer = new byte[4];
        }

        public override void Initialize()
        {
            _h = _key;
            _totalLength = 0;
            _idx = 0;
        }

        public override IHash Clone() =>
            new MurmurHash3_x86_32
            {
                _key = _key,
                _h = _h,
                _totalLength = _totalLength,
                _idx = _idx,
                _buffer = ArrayUtils.Clone(_buffer),
                BufferSize = BufferSize
            };

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var index = 0;
            var length = data.Length;
            var len = length;
            var idx = index;
            _totalLength += (uint)len;

            fixed (byte* dataPtr = data, bufferPtr = _buffer)
            {
                //consume last pending bytes
                uint block;
                if (_idx != 0 && length != 0)
                {
                    while (_idx < 4 && len != 0)
                    {
                        _buffer[_idx++] = *(dataPtr + index);
                        index++;
                        len--;
                    }

                    if (_idx == 4)
                    {
                        block = Converters.ReadBytesAsUInt32LE(bufferPtr, 0);
                        TransformUInt32Fast(block);
                        _idx = 0;
                    }
                }
                else
                {
                    idx = 0;
                }

                var nBlocks = len >> 2;

                // body
                var h = _h;
                var dataPtr2 = (uint*)(dataPtr + index);
                while (idx < nBlocks)
                {
                    block = Converters.ReadPCardinalAsUInt32LE(dataPtr2 + idx);
                    block *= C1;
                    block = Bits.RotateLeft32(block, 15);
                    block *= C2;

                    h ^= block;
                    h = Bits.RotateLeft32(h, 13);
                    h = h * 5 + C3;

                    idx++;
                }

                _h = h;

                //save pending end bytes
                var offset = index + idx * 4;
                while (offset < len + index)
                {
                    ByteUpdate(data[offset]);
                    offset++;
                }
            }
        }

        public override IHashResult TransformFinal()
        {
            Finish();
            var buffer = new byte[HashSize];
            Converters.ReadUInt32AsBytesBE(_h, buffer, 0);
            var result = new HashResult(buffer);
            Initialize();
            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void TransformUInt32Fast(uint block)
        {
            var h = _h;
            block *= C1;
            block = Bits.RotateLeft32(block, 15);
            block *= C2;

            h ^= block;
            h = Bits.RotateLeft32(h, 13);
            h = h * 5 + C3;

            _h = h;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void ByteUpdate(byte value)
        {
            _buffer[_idx++] = value;
            if (_idx < 4) return;
            fixed (byte* bufferPtr = _buffer)
            {
                var block = Converters.ReadBytesAsUInt32LE(bufferPtr, 0);
                TransformUInt32Fast(block);
                _idx = 0;
            }
        }

        private void Finish()
        {
            uint finalBlock = 0;

            // tail
            if (_idx != 0)
            {
                switch (_idx)
                {
                    case 3:
                        finalBlock ^= (uint)(_buffer[2] << 16);
                        finalBlock ^= (uint)(_buffer[1] << 8);
                        finalBlock ^= _buffer[0];
                        finalBlock *= C1;
                        finalBlock = Bits.RotateLeft32(finalBlock, 15);
                        finalBlock *= C2;
                        _h ^= finalBlock;
                        break;

                    case 2:
                        finalBlock ^= (uint)(_buffer[1] << 8);
                        finalBlock ^= _buffer[0];
                        finalBlock *= C1;
                        finalBlock = Bits.RotateLeft32(finalBlock, 15);
                        finalBlock *= C2;
                        _h ^= finalBlock;
                        break;

                    case 1:
                        finalBlock ^= _buffer[0];
                        finalBlock *= C1;
                        finalBlock = Bits.RotateLeft32(finalBlock, 15);
                        finalBlock *= C2;
                        _h ^= finalBlock;
                        break;
                }
            }

            // finalization
            _h ^= _totalLength;
            _h ^= _h >> 16;
            _h *= C4;
            _h ^= _h >> 13;
            _h *= C5;
            _h ^= _h >> 16;
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
    }
}