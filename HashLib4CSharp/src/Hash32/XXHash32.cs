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
    internal sealed class XXHash32 : Hash, IHash32, IHashWithKey, ITransformBlock
    {
        private uint _key, _hash;

        private const uint CKey = 0x0;

        private const uint PRIME32_1 = 2654435761;
        private const uint PRIME32_2 = 2246822519;
        private const uint PRIME32_3 = 3266489917;
        private const uint PRIME32_4 = 668265263;
        private const uint PRIME32_5 = 374761393;

        private unsafe struct XXH_State
        {
            internal ulong TotalLength;
            internal uint MemorySize, V1, V2, V3, V4;
            internal fixed byte Memory[16];

            internal XXH_State Clone()
            {
                var result = DefaultXXH_State();
                result.TotalLength = TotalLength;
                result.MemorySize = MemorySize;
                result.V1 = V1;
                result.V2 = V2;
                result.V3 = V3;
                result.V4 = V4;
                fixed (byte* ptrMemory = Memory)
                {
                    PointerUtils.MemMove(result.Memory, ptrMemory, 16);
                }
                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            internal static XXH_State DefaultXXH_State() => default;
        }

        private XXH_State _state;

        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        internal XXHash32()
            : base(4, 16)
        {
            _key = CKey;
            _state = XXH_State.DefaultXXH_State();
        }

        public override void Initialize()
        {
            _hash = 0;
            _state.V1 = _key + PRIME32_1 + PRIME32_2;
            _state.V2 = _key + PRIME32_2;
            _state.V3 = _key + 0;
            _state.V4 = _key - PRIME32_1;
            _state.TotalLength = 0;
            _state.MemorySize = 0;
        }

        public override IHash Clone() =>
            new XXHash32
            { _key = _key, _hash = _hash, _state = _state.Clone(), BufferSize = BufferSize };

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var length = data.Length;

            fixed (byte* dataPtr = data, memoryPtr = _state.Memory)
            {
                var dataPtr2 = dataPtr;
                _state.TotalLength += (ulong)length;

                byte* memoryPtr2;
                if (_state.MemorySize + (uint)length < 16)
                {
                    memoryPtr2 = memoryPtr + _state.MemorySize;

                    PointerUtils.MemMove(memoryPtr2, dataPtr2, length);

                    _state.MemorySize += (uint)length;

                    return;
                }

                var ptrEnd = dataPtr2 + (uint)length;

                if (_state.MemorySize > 0)
                {
                    memoryPtr2 = memoryPtr + _state.MemorySize;

                    PointerUtils.MemMove(memoryPtr2, dataPtr2, (int)(16 - _state.MemorySize));

                    _state.V1 = PRIME32_1 * Bits.RotateLeft32(
                        _state.V1 + PRIME32_2 * Converters.ReadBytesAsUInt32LE(memoryPtr, 0),
                        13);
                    _state.V2 = PRIME32_1 * Bits.RotateLeft32(
                        _state.V2 + PRIME32_2 * Converters.ReadBytesAsUInt32LE(memoryPtr, 4),
                        13);
                    _state.V3 = PRIME32_1 * Bits.RotateLeft32(
                        _state.V3 + PRIME32_2 * Converters.ReadBytesAsUInt32LE(memoryPtr, 8),
                        13);
                    _state.V4 = PRIME32_1 * Bits.RotateLeft32(
                        _state.V4 + PRIME32_2 * Converters.ReadBytesAsUInt32LE(memoryPtr, 12),
                        13);

                    dataPtr2 += 16 - _state.MemorySize;

                    _state.MemorySize = 0;
                }

                if (dataPtr2 <= ptrEnd - 16)
                {
                    var v1 = _state.V1;
                    var v2 = _state.V2;
                    var v3 = _state.V3;
                    var v4 = _state.V4;

                    var ptrLimit = ptrEnd - 16;

                    do
                    {
                        var dataPtrStart2 = (uint*)dataPtr2;
                        v1 = PRIME32_1 * Bits.RotateLeft32(
                            v1 + PRIME32_2 * Converters.ReadPCardinalAsUInt32LE(dataPtrStart2), 13);
                        v2 = PRIME32_1 * Bits.RotateLeft32(
                            v2 + PRIME32_2 * Converters.ReadPCardinalAsUInt32LE(dataPtrStart2 + 1), 13);
                        v3 = PRIME32_1 * Bits.RotateLeft32(
                            v3 + PRIME32_2 * Converters.ReadPCardinalAsUInt32LE(dataPtrStart2 + 2), 13);
                        v4 = PRIME32_1 * Bits.RotateLeft32(
                            v4 + PRIME32_2 * Converters.ReadPCardinalAsUInt32LE(dataPtrStart2 + 3), 13);
                        dataPtr2 += 16;
                    } while (dataPtr2 <= ptrLimit);

                    _state.V1 = v1;
                    _state.V2 = v2;
                    _state.V3 = v3;
                    _state.V4 = v4;
                }

                if (dataPtr2 >= ptrEnd) return;
                PointerUtils.MemMove(memoryPtr, dataPtr2, (int)(ptrEnd - dataPtr2));
                _state.MemorySize = (uint)(ptrEnd - dataPtr2);
            }
        }

        public override unsafe IHashResult TransformFinal()
        {
            fixed (byte* memoryPtr = _state.Memory)
            {
                if (_state.TotalLength >= 16)
                    _hash = Bits.RotateLeft32(_state.V1, 1) + Bits.RotateLeft32(_state.V2, 7) +
                            Bits.RotateLeft32(_state.V3, 12) + Bits.RotateLeft32(_state.V4, 18);
                else
                    _hash = _key + PRIME32_5;

                _hash += (uint)_state.TotalLength;

                var memoryPtr2 = memoryPtr;
                var ptrEnd = memoryPtr2 + _state.MemorySize;

                while (memoryPtr2 + 4 <= ptrEnd)
                {
                    _hash += Converters.ReadBytesAsUInt32LE(memoryPtr2, 0) * PRIME32_3;
                    _hash = Bits.RotateLeft32(_hash, 17) * PRIME32_4;
                    memoryPtr2 += 4;
                }

                while (memoryPtr2 < ptrEnd)
                {
                    _hash += *memoryPtr2 * PRIME32_5;
                    _hash = Bits.RotateLeft32(_hash, 11) * PRIME32_1;
                    memoryPtr2++;
                }

                _hash ^= _hash >> 15;
                _hash *= PRIME32_2;
                _hash ^= _hash >> 13;
                _hash *= PRIME32_3;
                _hash ^= _hash >> 16;
            }

            var result = new HashResult(_hash);

            Initialize();

            return result;
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