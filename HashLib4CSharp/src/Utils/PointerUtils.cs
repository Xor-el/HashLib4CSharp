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