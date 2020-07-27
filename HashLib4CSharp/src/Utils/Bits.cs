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
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace HashLib4CSharp.Utils
{
    internal static class Bits
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int Asr32(int value, int shiftBits) =>
            (int)(((uint)value >> (shiftBits & 31)) |
                   ((uint)(int)((0 - ((uint)value >> 31)) &
                                  (uint)(0 - Convert.ToInt32((shiftBits & 31) != 0))) <<
                    (32 - (shiftBits & 31))));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReverseBytesUInt32(uint value) => BinaryPrimitives.ReverseEndianness(value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReverseBytesUInt64(ulong value) => BinaryPrimitives.ReverseEndianness(value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint RotateLeft32(uint value, int offset) => (value << offset) | (value >> (32 - offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong RotateLeft64(ulong value, int offset) => (value << offset) | (value >> (64 - offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint RotateRight32(uint value, int offset) => (value >> offset) | (value << (32 - offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong RotateRight64(ulong value, int offset) => (value >> offset) | (value << (64 - offset));
    }
}