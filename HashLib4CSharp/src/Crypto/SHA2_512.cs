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
    internal sealed class SHA2_512 : SHA2_512Base
    {
        internal SHA2_512() :
            base(64)
        {
        }

        public override IHash Clone() =>
            new SHA2_512
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[0] = 0x6A09E667F3BCC908;
            State[1] = 0xBB67AE8584CAA73B;
            State[2] = 0x3C6EF372FE94F82B;
            State[3] = 0xA54FF53A5F1D36F1;
            State[4] = 0x510E527FADE682D1;
            State[5] = 0x9B05688C2B3E6C1F;
            State[6] = 0x1F83D9ABFB41BD6B;
            State[7] = 0x5BE0CD19137E2179;

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[8 * sizeof(ulong)];

            fixed (ulong* statePtr = State)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.be64_copy(statePtr, 0, resultPtr, 0, result.Length);
                }
            }

            return result;
        }
    }
}