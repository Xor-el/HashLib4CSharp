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
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HashLib4CSharp.Utils
{
    internal static class ArrayUtils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool AreEqual(byte[] left, byte[] right)
        {
            if (left == null) throw new ArgumentNullException(nameof(left));
            if (right == null) throw new ArgumentNullException(nameof(right));
            return left.SequenceEqual(right);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool ConstantTimeAreEqual(byte[] left, byte[] right)
        {
            if (left == null) throw new ArgumentNullException(nameof(left));
            if (right == null) throw new ArgumentNullException(nameof(right));
            return CryptographicOperations.FixedTimeEquals(left, right);
        }

        internal static void Fill<T>(T[] buffer, int from, int to, T filler)
        {
            if (buffer == null) return;
            while (from < to)
            {
                buffer[from] = filler;
                from++;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ZeroFill<T>(T[] buffer) => Fill(buffer, 0, buffer?.Length ?? 0, default);

        internal static void ZeroFill<T>(T[][] matrixBuffer)
        {
            if (matrixBuffer == null) return;
            foreach (var buffer in matrixBuffer)
                Fill(buffer, 0, buffer.Length, default);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static T[] Clone<T>(T[] buffer) => (T[]) buffer?.Clone();

        internal static T[][] Clone<T>(T[][] matrixBuffer)
        {
            if (matrixBuffer == null) return null;
            var matrixBufferLength = matrixBuffer.Length;
            var result = new T[matrixBufferLength][];
            for (var i = 0; i < matrixBufferLength; i++)
                result[i] = Clone(matrixBuffer[i]);

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static T[] Concatenate<T>(T[] left, T[] right)
        {
            if (left == null)
                return Clone(right);
            if (right == null)
                return Clone(left);

            var result = new T[left.Length + right.Length];
            Array.Copy(left, 0, result, 0, left.Length);
            Array.Copy(right, 0, result, left.Length, right.Length);
            return result;
        }
    }
}