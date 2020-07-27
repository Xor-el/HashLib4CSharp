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
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class RadioGatun32 : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private uint[] _mill;
        private uint[][] _belt;

        internal RadioGatun32()
            : base(32, 12)
        {
            _mill = new uint[19];
            _belt = new uint[13][];

            for (var i = 0; i < 13; i++)
                _belt[i] = new uint[3];
        }

        public override IHash Clone() =>
            new RadioGatun32
            {
                _mill = ArrayUtils.Clone(_mill),
                _belt = ArrayUtils.Clone(_belt),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            ArrayUtils.ZeroFill(_mill);
            ArrayUtils.ZeroFill(_belt);

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var buffer = stackalloc uint[HashSize / sizeof(uint)];
            var result = new byte[HashSize];

            fixed (uint* millPtr = _mill)
            {
                fixed (byte* resultPtr = result)
                {
                    for (var i = 0; i < 4; i++)
                    {
                        RoundFunction();
                        PointerUtils.MemMove(buffer + i * 2, millPtr + 1, 2 * sizeof(uint));
                    }

                    Converters.le32_copy(buffer, 0, resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        }

        protected override void Finish()
        {
            var paddingSize = 12 - (int)(ProcessedBytesCount % 12);

            Span<byte> pad = stackalloc byte[paddingSize];

            pad[0] = 0x01;

            TransformByteSpan(pad.Slice(0, paddingSize));

            for (var i = 0; i < 16; i++)
                RoundFunction();
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc uint[3];

            Converters.le32_copy(data, index, buffer, 0, dataLength);


            var i = 0;
            while (i < 3)
            {
                _mill[i + 16] = _mill[i + 16] ^ buffer[i];
                _belt[0][i] = _belt[0][i] ^ buffer[i];
                i++;
            }

            RoundFunction();
        }

        private unsafe void RoundFunction()
        {
            var a = stackalloc uint[19];
            var q = _belt[12];

            var i = 12;
            while (i > 0)
            {
                _belt[i] = _belt[i - 1];
                i--;
            }

            _belt[0] = q;

            i = 0;
            while (i < 12)
            {
                _belt[i + 1][i % 3] = _belt[i + 1][i % 3] ^ _mill[i + 1];
                i++;
            }

            i = 0;
            while (i < 19)
            {
                a[i] = _mill[i] ^ (_mill[(i + 1) % 19] | ~_mill[(i + 2) % 19]);
                i++;
            }

            i = 0;
            while (i < 19)
            {
                _mill[i] = Bits.RotateRight32(a[7 * i % 19], (i * (i + 1)) >> 1);
                i++;
            }

            i = 0;
            while (i < 19)
            {
                a[i] = _mill[i] ^ _mill[(i + 1) % 19] ^ _mill[(i + 4) % 19];
                i++;
            }

            a[0] = a[0] ^ 1;

            i = 0;
            while (i < 19)
            {
                _mill[i] = a[i];
                i++;
            }

            i = 0;
            while (i < 3)
            {
                _mill[i + 13] = _mill[i + 13] ^ q[i];
                i++;
            }
        }
    }
}