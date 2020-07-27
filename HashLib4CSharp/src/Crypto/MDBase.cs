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
    internal abstract class MDBase : BlockHash, ICryptoNotBuiltIn
    {
        protected const uint C1 = 0x50A28BE6;
        protected const uint C2 = 0x5A827999;
        protected const uint C3 = 0x5C4DD124;
        protected const uint C4 = 0x6ED9EBA1;
        protected const uint C5 = 0x6D703EF3;
        protected const uint C6 = 0x8F1BBCDC;
        protected const uint C7 = 0x7A6D76E9;
        protected const uint C8 = 0xA953FD4E;

        protected uint[] State;

        protected MDBase(int stateLength, int hashSize)
            : base(hashSize, 64)
        {
            State = new uint[stateLength];
        }

        public override void Initialize()
        {
            State[0] = 0x67452301;
            State[1] = 0xEFCDAB89;
            State[2] = 0x98BADCFE;
            State[3] = 0x10325476;

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (uint* statePtr = State)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy(statePtr, 0, resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        }

        protected override void Finish()
        {
            var bits = ProcessedBytesCount * 8;
            var padIndex = Buffer.Position < 56 ? 56 - Buffer.Position : 120 - Buffer.Position;

            Span<byte> pad = stackalloc byte[padIndex + 8];

            pad[0] = 0x80;

            bits = Converters.le2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, pad.Slice(padIndex));

            padIndex += 8;

            TransformByteSpan(pad.Slice(0, padIndex));
        }
    }
}