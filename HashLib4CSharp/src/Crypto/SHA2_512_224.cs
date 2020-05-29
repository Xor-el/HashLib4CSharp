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
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class SHA2_512_224 : SHA2_512Base
    {
        internal SHA2_512_224() :
            base(28)
        {
        }

        public override IHash Clone() =>
            new SHA2_512_224
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[0] = 0x8C3D37C819544DA2;
            State[1] = 0x73E1996689DCD4D6;
            State[2] = 0x1DFAB7AE32FF9C82;
            State[3] = 0x679DD514582F9FCF;
            State[4] = 0x0F6D2B697BD44DA8;
            State[5] = 0x77E36F7304C48942;
            State[6] = 0x3F9D85A86A1D36C8;
            State[7] = 0x1112E6AD91D692A1;

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[4 * sizeof(ulong)];

            fixed (ulong* statePtr = State)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.be64_copy(statePtr, 0, resultPtr, 0, result.Length);
                }
            }

            Array.Resize(ref result, HashSize);

            return result;
        }
    }
}