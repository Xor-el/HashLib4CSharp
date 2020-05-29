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
    internal sealed class SHA2_256 : SHA2_256Base
    {
        internal SHA2_256() :
            base(32)
        {
        }

        public override IHash Clone() =>
            new SHA2_256
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[0] = 0x6A09E667;
            State[1] = 0xBB67AE85;
            State[2] = 0x3C6EF372;
            State[3] = 0xA54FF53A;
            State[4] = 0x510E527F;
            State[5] = 0x9B05688C;
            State[6] = 0x1F83D9AB;
            State[7] = 0x5BE0CD19;

            base.Initialize();
        }
    }
}