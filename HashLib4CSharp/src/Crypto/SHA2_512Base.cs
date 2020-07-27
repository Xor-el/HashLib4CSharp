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
    internal abstract class SHA2_512Base : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        protected ulong[] State;

        protected SHA2_512Base(int hashSize)
            : base(hashSize, 128)
        {
            State = new ulong[8];
        }

        protected override void Finish()
        {
            var loBits = ProcessedBytesCount << 3;
            var hiBits = ProcessedBytesCount >> 61;

            var padIndex = Buffer.Position < 112 ? 111 - Buffer.Position : 239 - Buffer.Position;

            padIndex++;
     
            Span<byte> pad = stackalloc byte[padIndex + 16];

            pad[0] = 0x80;

            hiBits = Converters.be2me_64(hiBits);

            Converters.ReadUInt64AsBytesLE(hiBits, pad.Slice(padIndex));

            padIndex += 8;

            loBits = Converters.be2me_64(loBits);

            Converters.ReadUInt64AsBytesLE(loBits, pad.Slice(padIndex));

            padIndex += 8;

            TransformByteSpan(pad.Slice(0, padIndex));
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (ulong* statePtr = State)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.be64_copy(statePtr, 0, resultPtr, 0, result.Length);
                }
            }

            return result;
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc ulong[80];

            Converters.be64_copy(data, index, buffer, 0, dataLength);

            // Step 1

            var t0 = buffer[16 - 15];
            var t1 = buffer[16 - 2];
            buffer[16] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[16 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[0];
            t0 = buffer[17 - 15];
            t1 = buffer[17 - 2];
            buffer[17] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[17 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[17 - 16];
            t0 = buffer[18 - 15];
            t1 = buffer[18 - 2];
            buffer[18] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[18 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[18 - 16];
            t0 = buffer[19 - 15];
            t1 = buffer[19 - 2];
            buffer[19] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[19 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[19 - 16];
            t0 = buffer[20 - 15];
            t1 = buffer[20 - 2];
            buffer[20] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[20 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[20 - 16];
            t0 = buffer[21 - 15];
            t1 = buffer[21 - 2];
            buffer[21] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[21 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[21 - 16];
            t0 = buffer[22 - 15];
            t1 = buffer[22 - 2];
            buffer[22] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[22 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[22 - 16];
            t0 = buffer[23 - 15];
            t1 = buffer[23 - 2];
            buffer[23] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[23 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[23 - 16];
            t0 = buffer[24 - 15];
            t1 = buffer[24 - 2];
            buffer[24] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[24 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[24 - 16];
            t0 = buffer[25 - 15];
            t1 = buffer[25 - 2];
            buffer[25] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[25 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[25 - 16];
            t0 = buffer[26 - 15];
            t1 = buffer[26 - 2];
            buffer[26] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[26 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[26 - 16];
            t0 = buffer[27 - 15];
            t1 = buffer[27 - 2];
            buffer[27] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[27 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[27 - 16];
            t0 = buffer[28 - 15];
            t1 = buffer[28 - 2];
            buffer[28] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[28 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[28 - 16];
            t0 = buffer[29 - 15];
            t1 = buffer[29 - 2];
            buffer[29] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[29 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[29 - 16];
            t0 = buffer[30 - 15];
            t1 = buffer[30 - 2];
            buffer[30] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[30 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[30 - 16];
            t0 = buffer[31 - 15];
            t1 = buffer[31 - 2];
            buffer[31] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[31 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[31 - 16];
            t0 = buffer[32 - 15];
            t1 = buffer[32 - 2];
            buffer[32] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[32 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[32 - 16];
            t0 = buffer[33 - 15];
            t1 = buffer[33 - 2];
            buffer[33] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[33 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[33 - 16];
            t0 = buffer[34 - 15];
            t1 = buffer[34 - 2];
            buffer[34] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[34 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[34 - 16];
            t0 = buffer[35 - 15];
            t1 = buffer[35 - 2];
            buffer[35] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[35 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[35 - 16];
            t0 = buffer[36 - 15];
            t1 = buffer[36 - 2];
            buffer[36] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[36 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[36 - 16];
            t0 = buffer[37 - 15];
            t1 = buffer[37 - 2];
            buffer[37] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[37 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[37 - 16];
            t0 = buffer[38 - 15];
            t1 = buffer[38 - 2];
            buffer[38] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[38 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[38 - 16];
            t0 = buffer[39 - 15];
            t1 = buffer[39 - 2];
            buffer[39] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[39 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[39 - 16];
            t0 = buffer[40 - 15];
            t1 = buffer[40 - 2];
            buffer[40] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[40 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[40 - 16];
            t0 = buffer[41 - 15];
            t1 = buffer[41 - 2];
            buffer[41] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[41 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[41 - 16];
            t0 = buffer[42 - 15];
            t1 = buffer[42 - 2];
            buffer[42] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[42 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[42 - 16];
            t0 = buffer[43 - 15];
            t1 = buffer[43 - 2];
            buffer[43] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[43 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[43 - 16];
            t0 = buffer[44 - 15];
            t1 = buffer[44 - 2];
            buffer[44] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[44 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[44 - 16];
            t0 = buffer[45 - 15];
            t1 = buffer[45 - 2];
            buffer[45] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[45 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[45 - 16];
            t0 = buffer[46 - 15];
            t1 = buffer[46 - 2];
            buffer[46] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[46 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[46 - 16];
            t0 = buffer[47 - 15];
            t1 = buffer[47 - 2];
            buffer[47] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[47 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[47 - 16];
            t0 = buffer[48 - 15];
            t1 = buffer[48 - 2];
            buffer[48] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[48 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[48 - 16];
            t0 = buffer[49 - 15];
            t1 = buffer[49 - 2];
            buffer[49] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[49 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[49 - 16];
            t0 = buffer[50 - 15];
            t1 = buffer[50 - 2];
            buffer[50] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[50 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[50 - 16];
            t0 = buffer[51 - 15];
            t1 = buffer[51 - 2];
            buffer[51] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[51 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[51 - 16];
            t0 = buffer[52 - 15];
            t1 = buffer[52 - 2];
            buffer[52] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[52 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[52 - 16];
            t0 = buffer[53 - 15];
            t1 = buffer[53 - 2];
            buffer[53] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[53 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[53 - 16];
            t0 = buffer[54 - 15];
            t1 = buffer[54 - 2];
            buffer[54] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[54 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[54 - 16];
            t0 = buffer[55 - 15];
            t1 = buffer[55 - 2];
            buffer[55] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[55 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[55 - 16];
            t0 = buffer[56 - 15];
            t1 = buffer[56 - 2];
            buffer[56] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[56 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[56 - 16];
            t0 = buffer[57 - 15];
            t1 = buffer[57 - 2];
            buffer[57] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[57 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[57 - 16];
            t0 = buffer[58 - 15];
            t1 = buffer[58 - 2];
            buffer[58] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[58 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[58 - 16];
            t0 = buffer[59 - 15];
            t1 = buffer[59 - 2];
            buffer[59] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[59 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[59 - 16];
            t0 = buffer[60 - 15];
            t1 = buffer[60 - 2];
            buffer[60] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[60 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[60 - 16];
            t0 = buffer[61 - 15];
            t1 = buffer[61 - 2];
            buffer[61] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[61 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[61 - 16];
            t0 = buffer[62 - 15];
            t1 = buffer[62 - 2];
            buffer[62] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[62 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[62 - 16];
            t0 = buffer[63 - 15];
            t1 = buffer[63 - 2];
            buffer[63] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[63 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[63 - 16];
            t0 = buffer[64 - 15];
            t1 = buffer[64 - 2];
            buffer[64] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[64 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[64 - 16];
            t0 = buffer[65 - 15];
            t1 = buffer[65 - 2];
            buffer[65] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[65 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[65 - 16];
            t0 = buffer[66 - 15];
            t1 = buffer[66 - 2];
            buffer[66] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[66 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[66 - 16];
            t0 = buffer[67 - 15];
            t1 = buffer[67 - 2];
            buffer[67] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[67 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[67 - 16];
            t0 = buffer[68 - 15];
            t1 = buffer[68 - 2];
            buffer[68] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[68 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[68 - 16];
            t0 = buffer[69 - 15];
            t1 = buffer[69 - 2];
            buffer[69] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[69 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[69 - 16];
            t0 = buffer[70 - 15];
            t1 = buffer[70 - 2];
            buffer[70] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[70 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[70 - 16];
            t0 = buffer[71 - 15];
            t1 = buffer[71 - 2];
            buffer[71] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[71 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[71 - 16];
            t0 = buffer[72 - 15];
            t1 = buffer[72 - 2];
            buffer[72] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[72 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[72 - 16];
            t0 = buffer[73 - 15];
            t1 = buffer[73 - 2];
            buffer[73] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[73 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[73 - 16];
            t0 = buffer[74 - 15];
            t1 = buffer[74 - 2];
            buffer[74] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[74 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[74 - 16];
            t0 = buffer[75 - 15];
            t1 = buffer[75 - 2];
            buffer[75] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[75 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[75 - 16];
            t0 = buffer[76 - 15];
            t1 = buffer[76 - 2];
            buffer[76] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[76 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[76 - 16];
            t0 = buffer[77 - 15];
            t1 = buffer[77 - 2];
            buffer[77] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[77 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[77 - 16];
            t0 = buffer[78 - 15];
            t1 = buffer[78 - 2];
            buffer[78] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[78 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[78 - 16];
            t0 = buffer[79 - 15];
            t1 = buffer[79 - 2];
            buffer[79] = (Bits.RotateLeft64(t1, 45) ^ Bits.RotateLeft64(t1, 3)
                                                    ^ (t1 >> 6)) + buffer[79 - 7] +
                         (Bits.RotateLeft64(t0, 63) ^ Bits.RotateLeft64(t0, 56)
                                                    ^ (t0 >> 7)) + buffer[79 - 16];

            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var e = State[4];
            var f = State[5];
            var g = State[6];
            var h = State[7];

            // Step 2

            // R0
            h += 0x428A2F98D728AE22 + buffer[0] + (Bits.RotateLeft64(e, 50)
                                                   ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0x7137449123EF65CD + buffer[1] + (Bits.RotateLeft64(d, 50)
                                                   ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0xB5C0FBCFEC4D3B2F + buffer[2] + (Bits.RotateLeft64(c, 50)
                                                   ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0xE9B5DBA58189DBBC + buffer[3] + (Bits.RotateLeft64(b, 50)
                                                   ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x3956C25BF348B538 + buffer[4] + (Bits.RotateLeft64(a, 50)
                                                   ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0x59F111F1B605D019 + buffer[5] + (Bits.RotateLeft64(h, 50)
                                                   ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x923F82A4AF194F9B + buffer[6] + (Bits.RotateLeft64(g, 50)
                                                   ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0xAB1C5ED5DA6D8118 + buffer[7] + (Bits.RotateLeft64(f, 50)
                                                   ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R1
            h += 0xD807AA98A3030242 + buffer[8] + (Bits.RotateLeft64(e, 50)
                                                   ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0x12835B0145706FBE + buffer[9] + (Bits.RotateLeft64(d, 50)
                                                   ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0x243185BE4EE4B28C + buffer[10] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0x550C7DC3D5FFB4E2 + buffer[11] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x72BE5D74F27B896F + buffer[12] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0x80DEB1FE3B1696B1 + buffer[13] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x9BDC06A725C71235 + buffer[14] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0xC19BF174CF692694 + buffer[15] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R2

            h += 0xE49B69C19EF14AD2 + buffer[16] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0xEFBE4786384F25E3 + buffer[17] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0x0FC19DC68B8CD5B5 + buffer[18] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0x240CA1CC77AC9C65 + buffer[19] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x2DE92C6F592B0275 + buffer[20] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0x4A7484AA6EA6E483 + buffer[21] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x5CB0A9DCBD41FBD4 + buffer[22] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0x76F988DA831153B5 + buffer[23] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R3

            h += 0x983E5152EE66DFAB + buffer[24] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0xA831C66D2DB43210 + buffer[25] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0xB00327C898FB213F + buffer[26] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0xBF597FC7BEEF0EE4 + buffer[27] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0xC6E00BF33DA88FC2 + buffer[28] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0xD5A79147930AA725 + buffer[29] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x06CA6351E003826F + buffer[30] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0x142929670A0E6E70 + buffer[31] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R4

            h += 0x27B70A8546D22FFC + buffer[32] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0x2E1B21385C26C926 + buffer[33] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0x4D2C6DFC5AC42AED + buffer[34] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0x53380D139D95B3DF + buffer[35] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x650A73548BAF63DE + buffer[36] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0x766A0ABB3C77B2A8 + buffer[37] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x81C2C92E47EDAEE6 + buffer[38] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0x92722C851482353B + buffer[39] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R5

            h += 0xA2BFE8A14CF10364 + buffer[40] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0xA81A664BBC423001 + buffer[41] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0xC24B8B70D0F89791 + buffer[42] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0xC76C51A30654BE30 + buffer[43] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0xD192E819D6EF5218 + buffer[44] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0xD69906245565A910 + buffer[45] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0xF40E35855771202A + buffer[46] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0x106AA07032BBD1B8 + buffer[47] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R6

            h += 0x19A4C116B8D2D0C8 + buffer[48] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0x1E376C085141AB53 + buffer[49] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0x2748774CDF8EEB99 + buffer[50] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0x34B0BCB5E19B48A8 + buffer[51] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x391C0CB3C5C95A63 + buffer[52] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0x4ED8AA4AE3418ACB + buffer[53] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x5B9CCA4F7763E373 + buffer[54] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0x682E6FF3D6B2B8A3 + buffer[55] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R7

            h += 0x748F82EE5DEFB2FC + buffer[56] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0x78A5636F43172F60 + buffer[57] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0x84C87814A1F0AB72 + buffer[58] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0x8CC702081A6439EC + buffer[59] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x90BEFFFA23631E28 + buffer[60] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0xA4506CEBDE82BDE9 + buffer[61] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0xBEF9A3F7B2C67915 + buffer[62] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0xC67178F2E372532B + buffer[63] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R8

            h += 0xCA273ECEEA26619C + buffer[64] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0xD186B8C721C0C207 + buffer[65] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0xEADA7DD6CDE0EB1E + buffer[66] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0xF57D4F7FEE6ED178 + buffer[67] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x06F067AA72176FBA + buffer[68] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0x0A637DC5A2C898A6 + buffer[69] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x113F9804BEF90DAE + buffer[70] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0x1B710B35131C471B + buffer[71] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            // R9

            h += 0x28DB77F523047D84 + buffer[72] + (Bits.RotateLeft64(e, 50)
                                                    ^ Bits.RotateLeft64(e, 46) ^ Bits.RotateLeft64(e, 23)) +
                 ((e & f) ^ (~e & g));

            d += h;
            h += (Bits.RotateLeft64(a, 36) ^ Bits.RotateLeft64(a, 30)
                                           ^ Bits.RotateLeft64(a, 25)) + ((a & b) ^ (a & c) ^ (b & c));

            g += 0x32CAAB7B40C72493 + buffer[73] + (Bits.RotateLeft64(d, 50)
                                                    ^ Bits.RotateLeft64(d, 46) ^ Bits.RotateLeft64(d, 23)) +
                 ((d & e) ^ (~d & f));

            c += g;
            g += (Bits.RotateLeft64(h, 36) ^ Bits.RotateLeft64(h, 30)
                                           ^ Bits.RotateLeft64(h, 25)) + ((h & a) ^ (h & b) ^ (a & b));

            f += 0x3C9EBE0A15C9BEBC + buffer[74] + (Bits.RotateLeft64(c, 50)
                                                    ^ Bits.RotateLeft64(c, 46) ^ Bits.RotateLeft64(c, 23)) +
                 ((c & d) ^ (~c & e));

            b += f;
            f += (Bits.RotateLeft64(g, 36) ^ Bits.RotateLeft64(g, 30)
                                           ^ Bits.RotateLeft64(g, 25)) + ((g & h) ^ (g & a) ^ (h & a));

            e += 0x431D67C49C100D4C + buffer[75] + (Bits.RotateLeft64(b, 50)
                                                    ^ Bits.RotateLeft64(b, 46) ^ Bits.RotateLeft64(b, 23)) +
                 ((b & c) ^ (~b & d));

            a += e;
            e += (Bits.RotateLeft64(f, 36) ^ Bits.RotateLeft64(f, 30)
                                           ^ Bits.RotateLeft64(f, 25)) + ((f & g) ^ (f & h) ^ (g & h));

            d += 0x4CC5D4BECB3E42B6 + buffer[76] + (Bits.RotateLeft64(a, 50)
                                                    ^ Bits.RotateLeft64(a, 46) ^ Bits.RotateLeft64(a, 23)) +
                 ((a & b) ^ (~a & c));

            h += d;
            d += (Bits.RotateLeft64(e, 36) ^ Bits.RotateLeft64(e, 30)
                                           ^ Bits.RotateLeft64(e, 25)) + ((e & f) ^ (e & g) ^ (f & g));

            c += 0x597F299CFC657E2A + buffer[77] + (Bits.RotateLeft64(h, 50)
                                                    ^ Bits.RotateLeft64(h, 46) ^ Bits.RotateLeft64(h, 23)) +
                 ((h & a) ^ (~h & b));

            g += c;
            c += (Bits.RotateLeft64(d, 36) ^ Bits.RotateLeft64(d, 30)
                                           ^ Bits.RotateLeft64(d, 25)) + ((d & e) ^ (d & f) ^ (e & f));

            b += 0x5FCB6FAB3AD6FAEC + buffer[78] + (Bits.RotateLeft64(g, 50)
                                                    ^ Bits.RotateLeft64(g, 46) ^ Bits.RotateLeft64(g, 23)) +
                 ((g & h) ^ (~g & a));

            f += b;
            b += (Bits.RotateLeft64(c, 36) ^ Bits.RotateLeft64(c, 30)
                                           ^ Bits.RotateLeft64(c, 25)) + ((c & d) ^ (c & e) ^ (d & e));

            a += 0x6C44198C4A475817 + buffer[79] + (Bits.RotateLeft64(f, 50)
                                                    ^ Bits.RotateLeft64(f, 46) ^ Bits.RotateLeft64(f, 23)) +
                 ((f & g) ^ (~f & h));

            e += a;
            a += (Bits.RotateLeft64(b, 36) ^ Bits.RotateLeft64(b, 30)
                                           ^ Bits.RotateLeft64(b, 25)) + ((b & c) ^ (b & d) ^ (c & d));

            State[0] = State[0] + a;
            State[1] = State[1] + b;
            State[2] = State[2] + c;
            State[3] = State[3] + d;
            State[4] = State[4] + e;
            State[5] = State[5] + f;
            State[6] = State[6] + g;
            State[7] = State[7] + h;
        }
    }
}