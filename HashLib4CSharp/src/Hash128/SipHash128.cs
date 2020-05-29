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

using HashLib4CSharp.Base;
using HashLib4CSharp.Hash64;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash128
{
    internal abstract class SipHash128 : SipHash
    {
        protected SipHash128(int compressionRounds, int finalizationRounds) : base(16, 8)
        {
            CompressionRounds = compressionRounds;
            FinalizationRounds = finalizationRounds;
        }

        protected override byte GetMagicXor() => 0xEE;

        public override void Initialize()
        {
            base.Initialize();
            V01 ^= GetMagicXor();
        }

        public override IHashResult TransformFinal()
        {
            var finalBlock = ProcessFinalBlock();
            V03 ^= finalBlock;
            CompressTimes(CompressionRounds);
            V00 ^= finalBlock;
            V02 ^= GetMagicXor();
            CompressTimes(FinalizationRounds);
            var buffer = new byte[HashSize];
            Converters.ReadUInt64AsBytesLE(V00 ^ V01 ^ V02 ^ V03, buffer, 0);
            V01 ^= 0xDD;
            CompressTimes(FinalizationRounds);
            Converters.ReadUInt64AsBytesLE(V00 ^ V01 ^ V02 ^ V03, buffer, 8);
            var result = new HashResult(buffer);
            Initialize();
            return result;
        }
    }

    internal sealed class SipHash128_2_4 : SipHash128
    {
        internal SipHash128_2_4() : base(2, 4)
        {
        }

        public override IHash Clone() =>
            new SipHash128_2_4
            {
                V00 = V00,
                V01 = V01,
                V02 = V02,
                V03 = V03,
                Key00 = Key00,
                Key01 = Key01,
                TotalLength = TotalLength,
                CompressionRounds = CompressionRounds,
                FinalizationRounds = FinalizationRounds,
                Idx = Idx,
                Buffer = ArrayUtils.Clone(Buffer),
                BufferSize = BufferSize
            };
    }
}