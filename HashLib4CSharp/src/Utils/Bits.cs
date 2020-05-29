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

namespace HashLib4CSharp.Utils
{
    internal static class Bits
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int Asr32(int value, int shiftBits) =>
            (int) (((uint) value >> (shiftBits & 31)) |
                   ((uint) (int) ((0 - ((uint) value >> 31)) &
                                  (uint) (0 - Convert.ToInt32((shiftBits & 31) != 0))) <<
                    (32 - (shiftBits & 31))));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static long Asr64(long value, long shiftBits) =>
            (long) (((ulong) value >> (int) (shiftBits & 63)) |
                    (((0 - ((ulong) value >> 63)) &
                      (ulong) (0 - Convert.ToInt32((shiftBits & 63) != 0))) << (int) (64 - (shiftBits & 63))));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int ReverseBytesInt32(int value)
        {
            var i1 = value & 0xFF;
            var i2 = Asr32(value, 8) & 0xFF;
            var i3 = Asr32(value, 16) & 0xFF;
            var i4 = Asr32(value, 24) & 0xFF;

            return (i1 << 24) | (i2 << 16) | (i3 << 8) | (i4 << 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte ReverseBitsUInt8(byte value)
        {
            var result = (byte) (((value >> 1) & 0x55) | ((value << 1) & 0xAA));
            result = (byte) (((result >> 2) & 0x33) | ((result << 2) & 0xCC));
            return (byte) (((result >> 4) & 0x0F) | ((result << 4) & 0xF0));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ushort ReverseBytesUInt16(ushort value) =>
            (ushort) (((value & (uint) 0xFF) << 8) | ((value & (uint) 0xFF00) >> 8));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReverseBytesUInt32(uint value) =>
            ((value & 0x000000FF) << 24) |
            ((value & 0x0000FF00) << 8) |
            ((value & 0x00FF0000) >> 8) |
            ((value & 0xFF000000) >> 24);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReverseBytesUInt64(ulong value) =>
            ((value & 0x00000000000000FF) << 56) |
            ((value & 0x000000000000FF00) << 40) |
            ((value & 0x0000000000FF0000) << 24) |
            ((value & 0x00000000FF000000) << 8) |
            ((value & 0x000000FF00000000) >> 8) |
            ((value & 0x0000FF0000000000) >> 24) |
            ((value & 0x00FF000000000000) >> 40) |
            ((value & 0xFF00000000000000) >> 56);

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