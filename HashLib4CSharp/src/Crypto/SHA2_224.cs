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

using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class SHA2_224 : SHA2_256Base
    {
        internal SHA2_224() :
            base(28)
        {
        }

        public override IHash Clone() =>
            new SHA2_224
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[0] = 0xC1059ED8;
            State[1] = 0x367CD507;
            State[2] = 0x3070DD17;
            State[3] = 0xF70E5939;
            State[4] = 0xFFC00B31;
            State[5] = 0x68581511;
            State[6] = 0x64F98FA7;
            State[7] = 0xBEFA4FA4;

            base.Initialize();
        }
    }
}