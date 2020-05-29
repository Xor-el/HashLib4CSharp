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

using System.Runtime.CompilerServices;

namespace HashLib4CSharp.Utils
{
    internal static class PointerUtils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void MemMove(void* dest, void* src, int byteCount) =>
            Unsafe.CopyBlockUnaligned(dest, src, (uint) byteCount);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void MemSet(void* dest, byte filler, int byteCount) =>
            Unsafe.InitBlockUnaligned(dest, filler, (uint) byteCount);
    }
}