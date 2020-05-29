/*
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
{ *                             HashLib4CSharp Library                              * }
{ *                      Copyright (c) 2020 Ugochukwu Mmaduekwe                     * }
{ *                 GitHub Profile URL <https://github.com/Xor-el>                  * }

{ *  Distributed under the MIT software license, see the accompanying LICENSE file  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *   This library was sponsored by Sphere 10 Software (https://www.sphere10.com)   * }
{ *         for the purposes of supporting the XXX (https://YYY) project.           * }
{ *                                                                                 * }
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
*/

using System.Diagnostics;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Base
{
    internal sealed class HashBuffer
    {
        private const string HashBufferMessage = "HashBuffer, Length: {0}, Position: {1}, IsEmpty: {2}, IsFull: {3}";
        private byte[] _data;

        internal HashBuffer(int length)
        {
            Debug.Assert(length > 0);
            _data = new byte [length];
            Initialize();
        }

        internal bool IsEmpty => Position == 0;

        internal bool IsFull => Position == _data.Length;

        internal int Length => _data.Length;

        internal int Position { get; private set; }

        internal void Initialize()
        {
            Position = 0;
            ArrayUtils.ZeroFill(_data);
        }

        public override string ToString() => string.Format(HashBufferMessage, Length, Position, IsEmpty, IsFull);

        internal HashBuffer Clone()
        {
            var result = new HashBuffer(Length) {Position = Position, _data = ArrayUtils.Clone(_data)};
            return result;
        }

        internal byte[] GetBytes()
        {
            Debug.Assert(IsFull);
            Position = 0;
            return ArrayUtils.Clone(_data);
        }

        internal byte[] GetBytesZeroPadded()
        {
            ArrayUtils.Fill<byte>(_data, Position, _data.Length - Position +
                                                   Position, 0);
            Position = 0;
            return ArrayUtils.Clone(_data);
        }

        internal unsafe bool Feed(void* data, int dataLength, int length)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            Debug.Assert(length >= 0);
            Debug.Assert(length <= dataLength);
            Debug.Assert(!IsFull);

            if (dataLength == 0) return false;
            if (length == 0) return false;
            var size = _data.Length - Position;
            if (size > length) size = length;

            fixed (byte* dest = &_data[Position])
            {
                var src = (byte*) data;
                PointerUtils.MemMove(dest, src, size * sizeof(byte));
            }

            Position += size;

            return IsFull;
        }

        internal unsafe bool Feed(void* data, int dataLength,
            ref int startIndex, ref int length, ref ulong processedBytesCount)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            Debug.Assert(startIndex >= 0);
            Debug.Assert(length >= 0);
            Debug.Assert(startIndex + length <= dataLength);
            Debug.Assert(!IsFull);

            if (dataLength == 0) return false;
            if (length == 0) return false;

            var size = _data.Length - Position;
            if (size > length) size = length;

            fixed (byte* dest = &_data[Position])
            {
                var src = (byte*) data + startIndex;
                PointerUtils.MemMove(dest, src, size * sizeof(byte));
            }

            Position += size;
            startIndex += size;
            length -= size;
            processedBytesCount += (ulong) size;
            return IsFull;
        }
    }
}