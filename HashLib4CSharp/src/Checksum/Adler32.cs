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
using System.Runtime.InteropServices;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Checksum
{
    internal sealed class Adler32 : Hash, IChecksum, IHash32, ITransformBlock
    {
        private const uint ModAdler = 65521;
        private uint _a, _b;

        public Adler32()
            : base(4, 1)
        {
        }

        public override IHash Clone() => new Adler32 { _a = _a, _b = _b, BufferSize = BufferSize };

        public override void Initialize()
        {
            _a = 1;
            _b = 0;
        }

        public override IHashResult TransformFinal()
        {
            var buffer = new byte[HashSize];
            Converters.ReadUInt32AsBytesBE((_b << 16) | _a, buffer, 0);
            var result = new HashResult(buffer);
            Initialize();
            return result;
        }

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var a = _a;
            var b = _b;

            // We can defer the modulo operation:
            // a maximally grows from 65521 to 65521 + 255 * 3800
            // b maximally grows by 3800 * median(a) = 2090079800 < 2^31
            const int bigBlockSize = 3800;

            var buffer = data;
            var bigBlockCount = buffer.Length / bigBlockSize;
            if (Environment.Is64BitProcess)
            {
                while (bigBlockCount-- > 0)
                {
                    foreach (var word in MemoryMarshal.Cast<byte, ulong>(buffer.Slice(0, bigBlockSize)))
                    {
                        var lo = (uint)word;
                        a += lo & 0xFF;
                        b += a;

                        a += (lo >> 8) & 0xFF;
                        b += a;

                        a += (lo >> 16) & 0xFF;
                        b += a;

                        a += (lo >> 24) & 0xFF;
                        b += a;

                        var hi = (uint)(word >> 32);
                        a += hi & 0xFF;
                        b += a;

                        a += (hi >> 8) & 0xFF;
                        b += a;

                        a += (hi >> 16) & 0xFF;
                        b += a;

                        a += (hi >> 24) & 0xFF;
                        b += a;
                    }

                    a %= ModAdler;
                    b %= ModAdler;

                    buffer = buffer.Slice(bigBlockSize);
                }
            }
            else
            {
                while (bigBlockCount-- > 0)
                {
                    foreach (var value in buffer.Slice(0, bigBlockSize))
                    {
                        a += value;
                        b += a;
                    }

                    a %= ModAdler;
                    b %= ModAdler;

                    buffer = buffer.Slice(bigBlockSize);
                }
            }

            foreach (var value in buffer)
            {
                a += value;
                b += a;
            }

            a %= ModAdler;
            b %= ModAdler;

            _a = a;
            _b = b;
        }
    }
}