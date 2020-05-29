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
    internal sealed class SHA1 : SHA0
    {
        public override IHash Clone() =>
            new SHA1
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        protected override unsafe void Expand(uint* data)
        {
            var temp = data[16 - 3] ^ data[16 - 8] ^ data[16 - 14] ^ data[0];
            data[16] = Bits.RotateLeft32(temp, 1);
            temp = data[17 - 3] ^ data[17 - 8] ^ data[17 - 14] ^ data[17 - 16];
            data[17] = Bits.RotateLeft32(temp, 1);
            temp = data[18 - 3] ^ data[18 - 8] ^ data[18 - 14] ^ data[18 - 16];
            data[18] = Bits.RotateLeft32(temp, 1);
            temp = data[19 - 3] ^ data[19 - 8] ^ data[19 - 14] ^ data[19 - 16];
            data[19] = Bits.RotateLeft32(temp, 1);
            temp = data[20 - 3] ^ data[20 - 8] ^ data[20 - 14] ^ data[20 - 16];
            data[20] = Bits.RotateLeft32(temp, 1);
            temp = data[21 - 3] ^ data[21 - 8] ^ data[21 - 14] ^ data[21 - 16];
            data[21] = Bits.RotateLeft32(temp, 1);
            temp = data[22 - 3] ^ data[22 - 8] ^ data[22 - 14] ^ data[22 - 16];
            data[22] = Bits.RotateLeft32(temp, 1);
            temp = data[23 - 3] ^ data[23 - 8] ^ data[23 - 14] ^ data[23 - 16];
            data[23] = Bits.RotateLeft32(temp, 1);
            temp = data[24 - 3] ^ data[24 - 8] ^ data[24 - 14] ^ data[24 - 16];
            data[24] = Bits.RotateLeft32(temp, 1);
            temp = data[25 - 3] ^ data[25 - 8] ^ data[25 - 14] ^ data[25 - 16];
            data[25] = Bits.RotateLeft32(temp, 1);
            temp = data[26 - 3] ^ data[26 - 8] ^ data[26 - 14] ^ data[26 - 16];
            data[26] = Bits.RotateLeft32(temp, 1);
            temp = data[27 - 3] ^ data[27 - 8] ^ data[27 - 14] ^ data[27 - 16];
            data[27] = Bits.RotateLeft32(temp, 1);
            temp = data[28 - 3] ^ data[28 - 8] ^ data[28 - 14] ^ data[28 - 16];
            data[28] = Bits.RotateLeft32(temp, 1);
            temp = data[29 - 3] ^ data[29 - 8] ^ data[29 - 14] ^ data[29 - 16];
            data[29] = Bits.RotateLeft32(temp, 1);
            temp = data[30 - 3] ^ data[30 - 8] ^ data[30 - 14] ^ data[30 - 16];
            data[30] = Bits.RotateLeft32(temp, 1);
            temp = data[31 - 3] ^ data[31 - 8] ^ data[31 - 14] ^ data[31 - 16];
            data[31] = Bits.RotateLeft32(temp, 1);
            temp = data[32 - 3] ^ data[32 - 8] ^ data[32 - 14] ^ data[32 - 16];
            data[32] = Bits.RotateLeft32(temp, 1);
            temp = data[33 - 3] ^ data[33 - 8] ^ data[33 - 14] ^ data[33 - 16];
            data[33] = Bits.RotateLeft32(temp, 1);
            temp = data[34 - 3] ^ data[34 - 8] ^ data[34 - 14] ^ data[34 - 16];
            data[34] = Bits.RotateLeft32(temp, 1);
            temp = data[35 - 3] ^ data[35 - 8] ^ data[35 - 14] ^ data[35 - 16];
            data[35] = Bits.RotateLeft32(temp, 1);
            temp = data[36 - 3] ^ data[36 - 8] ^ data[36 - 14] ^ data[36 - 16];
            data[36] = Bits.RotateLeft32(temp, 1);
            temp = data[37 - 3] ^ data[37 - 8] ^ data[37 - 14] ^ data[37 - 16];
            data[37] = Bits.RotateLeft32(temp, 1);
            temp = data[38 - 3] ^ data[38 - 8] ^ data[38 - 14] ^ data[38 - 16];
            data[38] = Bits.RotateLeft32(temp, 1);
            temp = data[39 - 3] ^ data[39 - 8] ^ data[39 - 14] ^ data[39 - 16];
            data[39] = Bits.RotateLeft32(temp, 1);
            temp = data[40 - 3] ^ data[40 - 8] ^ data[40 - 14] ^ data[40 - 16];
            data[40] = Bits.RotateLeft32(temp, 1);
            temp = data[41 - 3] ^ data[41 - 8] ^ data[41 - 14] ^ data[41 - 16];
            data[41] = Bits.RotateLeft32(temp, 1);
            temp = data[42 - 3] ^ data[42 - 8] ^ data[42 - 14] ^ data[42 - 16];
            data[42] = Bits.RotateLeft32(temp, 1);
            temp = data[43 - 3] ^ data[43 - 8] ^ data[43 - 14] ^ data[43 - 16];
            data[43] = Bits.RotateLeft32(temp, 1);
            temp = data[44 - 3] ^ data[44 - 8] ^ data[44 - 14] ^ data[44 - 16];
            data[44] = Bits.RotateLeft32(temp, 1);
            temp = data[45 - 3] ^ data[45 - 8] ^ data[45 - 14] ^ data[45 - 16];
            data[45] = Bits.RotateLeft32(temp, 1);
            temp = data[46 - 3] ^ data[46 - 8] ^ data[46 - 14] ^ data[46 - 16];
            data[46] = Bits.RotateLeft32(temp, 1);
            temp = data[47 - 3] ^ data[47 - 8] ^ data[47 - 14] ^ data[47 - 16];
            data[47] = Bits.RotateLeft32(temp, 1);
            temp = data[48 - 3] ^ data[48 - 8] ^ data[48 - 14] ^ data[48 - 16];
            data[48] = Bits.RotateLeft32(temp, 1);
            temp = data[49 - 3] ^ data[49 - 8] ^ data[49 - 14] ^ data[49 - 16];
            data[49] = Bits.RotateLeft32(temp, 1);
            temp = data[50 - 3] ^ data[50 - 8] ^ data[50 - 14] ^ data[50 - 16];
            data[50] = Bits.RotateLeft32(temp, 1);
            temp = data[51 - 3] ^ data[51 - 8] ^ data[51 - 14] ^ data[51 - 16];
            data[51] = Bits.RotateLeft32(temp, 1);
            temp = data[52 - 3] ^ data[52 - 8] ^ data[52 - 14] ^ data[52 - 16];
            data[52] = Bits.RotateLeft32(temp, 1);
            temp = data[53 - 3] ^ data[53 - 8] ^ data[53 - 14] ^ data[53 - 16];
            data[53] = Bits.RotateLeft32(temp, 1);
            temp = data[54 - 3] ^ data[54 - 8] ^ data[54 - 14] ^ data[54 - 16];
            data[54] = Bits.RotateLeft32(temp, 1);
            temp = data[55 - 3] ^ data[55 - 8] ^ data[55 - 14] ^ data[55 - 16];
            data[55] = Bits.RotateLeft32(temp, 1);
            temp = data[56 - 3] ^ data[56 - 8] ^ data[56 - 14] ^ data[56 - 16];
            data[56] = Bits.RotateLeft32(temp, 1);
            temp = data[57 - 3] ^ data[57 - 8] ^ data[57 - 14] ^ data[57 - 16];
            data[57] = Bits.RotateLeft32(temp, 1);
            temp = data[58 - 3] ^ data[58 - 8] ^ data[58 - 14] ^ data[58 - 16];
            data[58] = Bits.RotateLeft32(temp, 1);
            temp = data[59 - 3] ^ data[59 - 8] ^ data[59 - 14] ^ data[59 - 16];
            data[59] = Bits.RotateLeft32(temp, 1);
            temp = data[60 - 3] ^ data[60 - 8] ^ data[60 - 14] ^ data[60 - 16];
            data[60] = Bits.RotateLeft32(temp, 1);
            temp = data[61 - 3] ^ data[61 - 8] ^ data[61 - 14] ^ data[61 - 16];
            data[61] = Bits.RotateLeft32(temp, 1);
            temp = data[62 - 3] ^ data[62 - 8] ^ data[62 - 14] ^ data[62 - 16];
            data[62] = Bits.RotateLeft32(temp, 1);
            temp = data[63 - 3] ^ data[63 - 8] ^ data[63 - 14] ^ data[63 - 16];
            data[63] = Bits.RotateLeft32(temp, 1);
            temp = data[64 - 3] ^ data[64 - 8] ^ data[64 - 14] ^ data[64 - 16];
            data[64] = Bits.RotateLeft32(temp, 1);
            temp = data[65 - 3] ^ data[65 - 8] ^ data[65 - 14] ^ data[65 - 16];
            data[65] = Bits.RotateLeft32(temp, 1);
            temp = data[66 - 3] ^ data[66 - 8] ^ data[66 - 14] ^ data[66 - 16];
            data[66] = Bits.RotateLeft32(temp, 1);
            temp = data[67 - 3] ^ data[67 - 8] ^ data[67 - 14] ^ data[67 - 16];
            data[67] = Bits.RotateLeft32(temp, 1);
            temp = data[68 - 3] ^ data[68 - 8] ^ data[68 - 14] ^ data[68 - 16];
            data[68] = Bits.RotateLeft32(temp, 1);
            temp = data[69 - 3] ^ data[69 - 8] ^ data[69 - 14] ^ data[69 - 16];
            data[69] = Bits.RotateLeft32(temp, 1);
            temp = data[70 - 3] ^ data[70 - 8] ^ data[70 - 14] ^ data[70 - 16];
            data[70] = Bits.RotateLeft32(temp, 1);
            temp = data[71 - 3] ^ data[71 - 8] ^ data[71 - 14] ^ data[71 - 16];
            data[71] = Bits.RotateLeft32(temp, 1);
            temp = data[72 - 3] ^ data[72 - 8] ^ data[72 - 14] ^ data[72 - 16];
            data[72] = Bits.RotateLeft32(temp, 1);
            temp = data[73 - 3] ^ data[73 - 8] ^ data[73 - 14] ^ data[73 - 16];
            data[73] = Bits.RotateLeft32(temp, 1);
            temp = data[74 - 3] ^ data[74 - 8] ^ data[74 - 14] ^ data[74 - 16];
            data[74] = Bits.RotateLeft32(temp, 1);
            temp = data[75 - 3] ^ data[75 - 8] ^ data[75 - 14] ^ data[75 - 16];
            data[75] = Bits.RotateLeft32(temp, 1);
            temp = data[76 - 3] ^ data[76 - 8] ^ data[76 - 14] ^ data[76 - 16];
            data[76] = Bits.RotateLeft32(temp, 1);
            temp = data[77 - 3] ^ data[77 - 8] ^ data[77 - 14] ^ data[77 - 16];
            data[77] = Bits.RotateLeft32(temp, 1);
            temp = data[78 - 3] ^ data[78 - 8] ^ data[78 - 14] ^ data[78 - 16];
            data[78] = Bits.RotateLeft32(temp, 1);
            temp = data[79 - 3] ^ data[79 - 8] ^ data[79 - 14] ^ data[79 - 16];
            data[79] = Bits.RotateLeft32(temp, 1);
        }
    }
}