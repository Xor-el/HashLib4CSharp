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
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;

namespace HashLib4CSharp.Utils
{
    public static class Converters
    {
        private static unsafe void swap_copy_str_to_u32(void* src, int srcIndex,
            void* dest, int destIndex, int size)
        {
            // if all pointers and size are 32-bits aligned
            if ((((int)((byte*)dest - (byte*)0) | (int)((byte*)src - (byte*)0) | srcIndex |
                  destIndex | size) & 3) == 0)
            {
                // copy aligned memory block as 32-bit integers
                var srcStart = (uint*)((byte*)src + srcIndex);
                var srcEnd = (uint*)((byte*)src + srcIndex + size);
                var destStart = (uint*)((byte*)dest + destIndex);
                while (srcStart < srcEnd)
                {
                    *destStart = Bits.ReverseBytesUInt32(*srcStart);
                    destStart++;
                    srcStart++;
                }
            }
            else
            {
                var srcStart = (byte*)src + srcIndex;

                var count = size + destIndex;
                while (destIndex < count)
                {
                    ((byte*)dest)[destIndex ^ 3] = *srcStart;
                    srcStart++;
                    destIndex++;
                }
            }
        }

        private static unsafe void swap_copy_str_to_u64(void* src, int srcIndex,
            void* dest, int destIndex, int size)
        {
            // if all pointers and size are 64-bits aligned
            if ((((int)((byte*)dest - (byte*)0) | (int)((byte*)src - (byte*)0) | srcIndex |
                  destIndex | size) & 7) == 0)
            {
                // copy aligned memory block as 64-bit integers
                var srcStart = (ulong*)((byte*)src + srcIndex);
                var srcEnd = (ulong*)((byte*)src + srcIndex + size);
                var destStart = (ulong*)((byte*)dest + destIndex);
                while (srcStart < srcEnd)
                {
                    *destStart = Bits.ReverseBytesUInt64(*srcStart);
                    destStart++;
                    srcStart++;
                }
            }
            else
            {
                var srcStart = (byte*)src + srcIndex;

                var count = size + destIndex;
                while (destIndex < count)
                {
                    ((byte*)dest)[destIndex ^ 7] = *srcStart;
                    srcStart++;
                    destIndex++;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint be2me_32(uint value) =>
            BitConverter.IsLittleEndian ? Bits.ReverseBytesUInt32(value) : value;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong be2me_64(ulong value) =>
            BitConverter.IsLittleEndian ? Bits.ReverseBytesUInt64(value) : value;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void be32_copy(void* src, int srcIndex,
            void* dest, int destIndex, int size)
        {
            if (BitConverter.IsLittleEndian)
                swap_copy_str_to_u32(src, srcIndex, dest, destIndex, size);
            else
                PointerUtils.MemMove((byte*)dest + destIndex, (byte*)src + srcIndex, size);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void be64_copy(void* src, int srcIndex,
            void* dest, int destIndex, int size)
        {
            if (BitConverter.IsLittleEndian)
                swap_copy_str_to_u64(src, srcIndex, dest, destIndex, size);
            else
                PointerUtils.MemMove((byte*)dest + destIndex, (byte*)src + srcIndex, size);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint le2me_32(uint value) =>
            BitConverter.IsLittleEndian ? value : Bits.ReverseBytesUInt32(value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong le2me_64(ulong value) =>
            BitConverter.IsLittleEndian ? value : Bits.ReverseBytesUInt64(value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void le32_copy(void* src, int srcIndex,
            void* dest, int destIndex, int size)
        {
            if (BitConverter.IsLittleEndian)
                PointerUtils.MemMove((byte*)dest + destIndex, (byte*)src + srcIndex, size);
            else
                swap_copy_str_to_u32(src, srcIndex, dest, destIndex, size);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void le64_copy(void* src, int srcIndex,
            void* dest, int destIndex, int size)
        {
            if (BitConverter.IsLittleEndian)
                PointerUtils.MemMove((byte*)dest + destIndex, (byte*)src + srcIndex, size);
            else
                swap_copy_str_to_u64(src, srcIndex, dest, destIndex, size);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt32AsBytesLE(uint value,
            byte[] output, int index) =>
            ReadUInt32AsBytesLE(value, output.AsSpan().Slice(index));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt32AsBytesLE(uint value,
            Span<byte> output) =>
            BinaryPrimitives.WriteUInt32LittleEndian(output, value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt32AsBytesBE(uint value,
            byte[] output, int index) =>
            ReadUInt32AsBytesBE(value, output.AsSpan().Slice(index));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt32AsBytesBE(uint value,
            Span<byte> output) =>
            BinaryPrimitives.WriteUInt32BigEndian(output, value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt64AsBytesLE(ulong value,
            byte[] output, int index) =>
            ReadUInt64AsBytesLE(value, output.AsSpan().Slice(index));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt64AsBytesLE(ulong value,
            Span<byte> output) =>
            BinaryPrimitives.WriteUInt64LittleEndian(output, value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt64AsBytesBE(ulong value,
            byte[] output, int index) =>
            ReadUInt64AsBytesBE(value, output.AsSpan().Slice(index));


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ReadUInt64AsBytesBE(ulong value,
            Span<byte> output) =>
            BinaryPrimitives.WriteUInt64BigEndian(output, value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe uint ReadPCardinalAsUInt32(uint* input) => Unsafe.ReadUnaligned<uint>(input);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe ulong ReadPUInt64AsUInt64(ulong* input) => Unsafe.ReadUnaligned<ulong>(input);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe uint ReadPCardinalAsUInt32LE(uint* input) => le2me_32(ReadPCardinalAsUInt32(input));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe ulong ReadPUInt64AsUInt64LE(ulong* input) => le2me_64(ReadPUInt64AsUInt64(input));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe uint ReadPCardinalAsUInt32BE(uint* input) => be2me_32(ReadPCardinalAsUInt32(input));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe ulong ReadPUInt64AsUInt64BE(ulong* input) => be2me_64(ReadPUInt64AsUInt64(input));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe uint ReadBytesAsUInt32LE(byte* input, int index) =>
            ReadPCardinalAsUInt32LE((uint*)(input + index));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe ulong ReadBytesAsUInt64LE(byte* input, int index) =>
            ReadPUInt64AsUInt64LE((ulong*)(input + index));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe uint ReadBytesAsUInt32BE(byte* input, int index) =>
            ReadPCardinalAsUInt32BE((uint*)(input + index));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe ulong ReadBytesAsUInt64BE(byte* input, int index) =>
            ReadPUInt64AsUInt64BE((ulong*)(input + index));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] ReadUInt32AsBytesLE(uint input)
        {
            var result = new byte[sizeof(uint)];
            ReadUInt32AsBytesLE(input, result, 0);
            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] ReadUInt64AsBytesLE(ulong input)
        {
            var result = new byte[sizeof(ulong)];
            ReadUInt64AsBytesLE(input, result, 0);
            return result;
        }

        public static byte[] ConvertHexStringToBytes(string input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            input = input.Replace("-", string.Empty);
            var inputLength = input.Length;
            if (inputLength == 0) return new byte[0];
            Debug.Assert((inputLength & 1) == 0);
            var result = new byte[inputLength >> 1];
            for (var index = 0; index < result.Length; index++)
            {
                var byteValue = input.Substring(index * 2, 2);
                result[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return result;
        }

        public static string ConvertBytesToHexString(byte[] input, bool group = false)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (input.Length == 0) return "";
            var result = BitConverter.ToString(input);
            return group ? result : result.Replace("-", string.Empty);
        }

        public static byte[] ConvertStringToBytes(string input, Encoding encoding)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));
            return input.Length == 0 ? new byte[0] : encoding.GetBytes(input);
        }
    }
}