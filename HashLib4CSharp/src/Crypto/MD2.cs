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
    internal sealed class MD2 : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private static readonly byte[] Pi =
        {
            41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
            19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
            30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18, 190, 78,
            196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121,
            145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144,
            50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209, 215,
            94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107,
            226, 156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45,
            168, 2, 27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71,
            163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133,
            40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250,
            36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213,
            254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117,
            75, 10, 49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20
        };

        private byte[] _checksum;
        private byte[] _state;

        internal MD2()
            : base(16, 16)
        {
            _state = new byte[16];
            _checksum = new byte[16];
        }

        public override IHash Clone() =>
            new MD2
            {
                _state = ArrayUtils.Clone(_state),
                _checksum = ArrayUtils.Clone(_checksum),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            ArrayUtils.ZeroFill(_state);
            ArrayUtils.ZeroFill(_checksum);
            base.Initialize();
        }

        protected override byte[] GetResult() => ArrayUtils.Clone(_state);

        protected override void Finish()
        {
            var padLength = 16 - (uint)Buffer.Position;

            Span<byte> pad = stackalloc byte[(int)padLength];

            var idx = 0;
            while (idx < padLength)
            {
                pad[idx] = (byte)padLength;
                idx++;
            }

            TransformByteSpan(pad.Slice(0, (int)padLength));
            TransformByteSpan(_checksum.AsSpan().Slice(0, 16));
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            uint t = 0;
            var temp = stackalloc byte[48];

            fixed (byte* statePtr = _state)
            {
                PointerUtils.MemMove(temp, statePtr, dataLength);
                PointerUtils.MemMove(temp + dataLength, (byte*)data + index,
                    dataLength);

                for (var i = 0; i < 16; i++) temp[i + 32] = (byte)(_state[i] ^ ((byte*)data)[i + index]);

                for (var i = 0; i < 18; i++)
                {
                    for (var j = 0; j < 48; j++)
                    {
                        temp[j] = (byte)(temp[j] ^ Pi[t]);
                        t = temp[j];
                    }

                    t = (byte)(t + i);
                }

                PointerUtils.MemMove(statePtr, temp, 16);

                t = _checksum[15];

                for (var i = 0; i < 16; i++)
                {
                    _checksum[i] = (byte)(_checksum[i] ^ Pi[((byte*)data)[i + index] ^ t]);
                    t = _checksum[i];
                }

            }
        }
    }
}