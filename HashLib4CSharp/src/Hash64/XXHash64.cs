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
    internal sealed class XXHash64 : Hash, IHash64, IHashWithKey, ITransformBlock
    {
        private ulong _key, _hash;

        private const uint CKey = 0x0;

        private const ulong PRIME64_1 = 11400714785074694791;
        private const ulong PRIME64_2 = 14029467366897019727;
        private const ulong PRIME64_3 = 1609587929392839161;
        private const ulong PRIME64_4 = 9650029242287828579;
        private const ulong PRIME64_5 = 2870177450012600261;

        private unsafe struct XXH_State
        {
            internal ulong TotalLength, V1, V2, V3, V4;
            internal uint MemorySize;
            internal fixed byte Memory[32];

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
                    PointerUtils.MemMove(result.Memory, ptrMemory, 32);
                }
                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            internal static XXH_State DefaultXXH_State() => default;
        }

        private XXH_State _state;

        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        internal XXHash64()
            : base(8, 32)
        {
            _key = CKey;
            _state = XXH_State.DefaultXXH_State();
        }

        public override void Initialize()
        {
            _hash = 0;
            _state.V1 = _key + PRIME64_1 + PRIME64_2;
            _state.V2 = _key + PRIME64_2;
            _state.V3 = _key + 0;
            _state.V4 = _key - PRIME64_1;
            _state.TotalLength = 0;
            _state.MemorySize = 0;
        }

        public override IHash Clone() =>
            new XXHash64
            {
                _key = _key,
                _hash = _hash,
                _state = _state.Clone(),
                BufferSize = BufferSize
            };

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var length = data.Length;

            fixed (byte* dataPtr = data, memoryPtr = _state.Memory)
            {
                var dataPtr2 = dataPtr;
                _state.TotalLength += (ulong)length;

                byte* memoryPtr2;
                if (_state.MemorySize + (uint)length < 32)
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

                    PointerUtils.MemMove(memoryPtr2, dataPtr2, (int)(32 - _state.MemorySize));

                    _state.V1 = PRIME64_1 * Bits.RotateLeft64(
                        _state.V1 + PRIME64_2 * Converters.ReadBytesAsUInt64LE(memoryPtr, 0), 31);
                    _state.V2 = PRIME64_1 * Bits.RotateLeft64(
                        _state.V2 + PRIME64_2 * Converters.ReadBytesAsUInt64LE(memoryPtr, 8), 31);
                    _state.V3 = PRIME64_1 * Bits.RotateLeft64(
                        _state.V3 + PRIME64_2 * Converters.ReadBytesAsUInt64LE(memoryPtr, 16), 31);
                    _state.V4 = PRIME64_1 * Bits.RotateLeft64(
                        _state.V4 + PRIME64_2 * Converters.ReadBytesAsUInt64LE(memoryPtr, 24), 31);

                    dataPtr2 += 32 - _state.MemorySize;
                    _state.MemorySize = 0;
                }

                if (dataPtr2 <= ptrEnd - 32)
                {
                    var v1 = _state.V1;
                    var v2 = _state.V2;
                    var v3 = _state.V3;
                    var v4 = _state.V4;

                    var ptrLimit = ptrEnd - 32;

                    do
                    {
                        var dataPtrStart2 = (ulong*)dataPtr2;
                        v1 = PRIME64_1 * Bits.RotateLeft64(
                            v1 + PRIME64_2 * Converters.ReadPUInt64AsUInt64LE(dataPtrStart2), 31);
                        v2 = PRIME64_1 * Bits.RotateLeft64(
                            v2 + PRIME64_2 * Converters.ReadPUInt64AsUInt64LE(dataPtrStart2 + 1), 31);
                        v3 = PRIME64_1 * Bits.RotateLeft64(
                            v3 + PRIME64_2 * Converters.ReadPUInt64AsUInt64LE(dataPtrStart2 + 2), 31);
                        v4 = PRIME64_1 * Bits.RotateLeft64(
                            v4 + PRIME64_2 * Converters.ReadPUInt64AsUInt64LE(dataPtrStart2 + 3), 31);
                        dataPtr2 += 32;
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
                if (_state.TotalLength >= 32)
                {
                    var v1 = _state.V1;
                    var v2 = _state.V2;
                    var v3 = _state.V3;
                    var v4 = _state.V4;

                    _hash = Bits.RotateLeft64(v1, 1) + Bits.RotateLeft64(v2, 7) + Bits.RotateLeft64(v3, 12) +
                            Bits.RotateLeft64(v4, 18);

                    v1 = Bits.RotateLeft64(v1 * PRIME64_2, 31) * PRIME64_1;
                    _hash = (_hash ^ v1) * PRIME64_1 + PRIME64_4;

                    v2 = Bits.RotateLeft64(v2 * PRIME64_2, 31) * PRIME64_1;
                    _hash = (_hash ^ v2) * PRIME64_1 + PRIME64_4;

                    v3 = Bits.RotateLeft64(v3 * PRIME64_2, 31) * PRIME64_1;
                    _hash = (_hash ^ v3) * PRIME64_1 + PRIME64_4;

                    v4 = Bits.RotateLeft64(v4 * PRIME64_2, 31) * PRIME64_1;
                    _hash = (_hash ^ v4) * PRIME64_1 + PRIME64_4;
                }
                else
                    _hash = _key + PRIME64_5;

                _hash += _state.TotalLength;

                var memoryPtr2 = memoryPtr;
                var ptrEnd = memoryPtr2 + _state.MemorySize;

                while (memoryPtr2 + 8 <= ptrEnd)
                {
                    _hash ^= PRIME64_1 * Bits.RotateLeft64(PRIME64_2 * Converters.ReadBytesAsUInt64LE(memoryPtr2, 0),
                        31);
                    _hash = Bits.RotateLeft64(_hash, 27) * PRIME64_1 + PRIME64_4;
                    memoryPtr2 += 8;
                }

                if (memoryPtr2 + 4 <= ptrEnd)
                {
                    _hash ^= Converters.ReadBytesAsUInt32LE(memoryPtr2, 0) * PRIME64_1;
                    _hash = Bits.RotateLeft64(_hash, 23) * PRIME64_2 + PRIME64_3;
                    memoryPtr2 += 4;
                }

                while (memoryPtr2 < ptrEnd)
                {
                    _hash ^= *memoryPtr2 * PRIME64_5;
                    _hash = Bits.RotateLeft64(_hash, 11) * PRIME64_1;
                    memoryPtr2++;
                }

                _hash ^= _hash >> 33;
                _hash *= PRIME64_2;
                _hash ^= _hash >> 29;
                _hash *= PRIME64_3;
                _hash ^= _hash >> 32;
            }

            var result = new HashResult(_hash);

            Initialize();

            return result;
        }

        public int KeyLength => 8;

        public unsafe byte[] Key
        {
            get => Converters.ReadUInt64AsBytesLE(_key);
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
                        _key = Converters.ReadBytesAsUInt64LE(valuePtr, 0);
                    }
                }
            }
        }
    }
}