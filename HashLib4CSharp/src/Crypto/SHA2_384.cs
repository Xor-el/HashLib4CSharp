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
    internal sealed class SHA2_384 : SHA2_512Base
    {
        internal SHA2_384() :
            base(48)
        {
        }

        public override IHash Clone() =>
            new SHA2_384
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[0] = 0xCBBB9D5DC1059ED8;
            State[1] = 0x629A292A367CD507;
            State[2] = 0x9159015A3070DD17;
            State[3] = 0x152FECD8F70E5939;
            State[4] = 0x67332667FFC00B31;
            State[5] = 0x8EB44A8768581511;
            State[6] = 0xDB0C2E0D64F98FA7;
            State[7] = 0x47B5481DBEFA4FA4;

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[6 * sizeof(ulong)];

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