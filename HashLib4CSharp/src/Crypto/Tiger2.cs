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

using HashLib4CSharp.Enum;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal abstract class Tiger2 : Tiger
    {
        protected Tiger2(int hashSize, HashRounds rounds)
            : base(hashSize, rounds)
        {
        }

        protected override byte PaddingValue() => 0x80;
    }

    internal sealed class Tiger2_128 : Tiger2
    {
        public override IHash Clone() =>
            new Tiger2_128(Enum.HashSize.HashSize128, GetHashRound(Rounds))
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        private Tiger2_128(HashSize hashSize, HashRounds rounds)
            : base((int) hashSize, rounds)
        {
        }

        internal static IHash CreateRound3() => new Tiger2_128(Enum.HashSize.HashSize128, HashRounds.Rounds3);

        internal static IHash CreateRound4() => new Tiger2_128(Enum.HashSize.HashSize128, HashRounds.Rounds4);

        internal static IHash CreateRound5() => new Tiger2_128(Enum.HashSize.HashSize128, HashRounds.Rounds5);
    }

    internal sealed class Tiger2_160 : Tiger2
    {
        public override IHash Clone() =>
            new Tiger2_160(Enum.HashSize.HashSize160, GetHashRound(Rounds))
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        private Tiger2_160(HashSize hashSize, HashRounds rounds)
            : base((int) hashSize, rounds)
        {
        }

        internal static IHash CreateRound3() => new Tiger2_160(Enum.HashSize.HashSize160, HashRounds.Rounds3);

        internal static IHash CreateRound4() => new Tiger2_160(Enum.HashSize.HashSize160, HashRounds.Rounds4);

        internal static IHash CreateRound5() => new Tiger2_160(Enum.HashSize.HashSize160, HashRounds.Rounds5);
    }

    internal sealed class Tiger2_192 : Tiger2
    {
        public override IHash Clone() =>
            new Tiger2_192(Enum.HashSize.HashSize192, GetHashRound(Rounds))
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        private Tiger2_192(HashSize hashSize, HashRounds rounds)
            : base((int) hashSize, rounds)
        {
        }

        internal static IHash CreateRound3() => new Tiger2_192(Enum.HashSize.HashSize192, HashRounds.Rounds3);

        internal static IHash CreateRound4() => new Tiger2_192(Enum.HashSize.HashSize192, HashRounds.Rounds4);

        internal static IHash CreateRound5() => new Tiger2_192(Enum.HashSize.HashSize192, HashRounds.Rounds5);
    }
}