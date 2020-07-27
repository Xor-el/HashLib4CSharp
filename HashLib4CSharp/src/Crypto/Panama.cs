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
    internal sealed class Panama : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private uint[][] _stages;
        private uint[] _state, _theta, _gamma, _pi;

        private int _tap;

        internal Panama()
            : base(32, 32)
        {
            _tap = 0;
            _state = new uint[17];
            _theta = new uint[17];
            _gamma = new uint[17];
            _pi = new uint[17];
            _stages = new uint[32][];
            for (var i = 0; i < 32; i++)
                _stages[i] = new uint[8];
        }

        public override IHash Clone() =>
            new Panama
            {
                _state = ArrayUtils.Clone(_state),
                _theta = ArrayUtils.Clone(_theta),
                _gamma = ArrayUtils.Clone(_gamma),
                _pi = ArrayUtils.Clone(_pi),
                _stages = ArrayUtils.Clone(_stages),
                Buffer = Buffer.Clone(),
                _tap = _tap,
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            _tap = 0;
            ArrayUtils.ZeroFill(_state);
            ArrayUtils.ZeroFill(_theta);
            ArrayUtils.ZeroFill(_gamma);
            ArrayUtils.ZeroFill(_pi);
            ArrayUtils.ZeroFill(_stages);
            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (uint* statePtr = &_state[9])
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy(statePtr, 0, resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        }

        protected override unsafe void Finish()
        {
            var paddingSize = 32 - (int)(ProcessedBytesCount & 31);

            Span<byte> pad = stackalloc byte[paddingSize];

            pad[0] = 0x01;
            TransformByteSpan(pad.Slice(0, paddingSize));

            var theta = stackalloc uint[17];

            for (var i = 0; i < 32; i++)
            {
                var tap4 = (_tap + 4) & 0x1F;
                var tap16 = (_tap + 16) & 0x1F;

                _tap = (_tap - 1) & 0x1F;
                var tap25 = (_tap + 25) & 0x1F;

                Gpt(theta);

                _stages[tap25][0] = _stages[tap25][0] ^ _stages[_tap][2];
                _stages[tap25][1] = _stages[tap25][1] ^ _stages[_tap][3];
                _stages[tap25][2] = _stages[tap25][2] ^ _stages[_tap][4];
                _stages[tap25][3] = _stages[tap25][3] ^ _stages[_tap][5];
                _stages[tap25][4] = _stages[tap25][4] ^ _stages[_tap][6];
                _stages[tap25][5] = _stages[tap25][5] ^ _stages[_tap][7];
                _stages[tap25][6] = _stages[tap25][6] ^ _stages[_tap][0];
                _stages[tap25][7] = _stages[tap25][7] ^ _stages[_tap][1];
                _stages[_tap][0] = _stages[_tap][0] ^ _state[1];
                _stages[_tap][1] = _stages[_tap][1] ^ _state[2];
                _stages[_tap][2] = _stages[_tap][2] ^ _state[3];
                _stages[_tap][3] = _stages[_tap][3] ^ _state[4];
                _stages[_tap][4] = _stages[_tap][4] ^ _state[5];
                _stages[_tap][5] = _stages[_tap][5] ^ _state[6];
                _stages[_tap][6] = _stages[_tap][6] ^ _state[7];
                _stages[_tap][7] = _stages[_tap][7] ^ _state[8];

                _state[0] = theta[0] ^ 0x01;
                _state[1] = theta[1] ^ _stages[tap4][0];
                _state[2] = theta[2] ^ _stages[tap4][1];
                _state[3] = theta[3] ^ _stages[tap4][2];
                _state[4] = theta[4] ^ _stages[tap4][3];
                _state[5] = theta[5] ^ _stages[tap4][4];
                _state[6] = theta[6] ^ _stages[tap4][5];
                _state[7] = theta[7] ^ _stages[tap4][6];
                _state[8] = theta[8] ^ _stages[tap4][7];
                _state[9] = theta[9] ^ _stages[tap16][0];
                _state[10] = theta[10] ^ _stages[tap16][1];
                _state[11] = theta[11] ^ _stages[tap16][2];
                _state[12] = theta[12] ^ _stages[tap16][3];
                _state[13] = theta[13] ^ _stages[tap16][4];
                _state[14] = theta[14] ^ _stages[tap16][5];
                _state[15] = theta[15] ^ _stages[tap16][6];
                _state[16] = theta[16] ^ _stages[tap16][7];
            }
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            uint tap16, tap25;

            var buffer = stackalloc uint[17];

            fixed (uint* thetaPtr = _theta)
            {
                Converters.le32_copy(data, index, buffer, 0, dataLength);

                tap16 = (uint)((_tap + 16) & 0x1F);

                _tap = (_tap - 1) & 0x1F;
                tap25 = (uint)((_tap + 25) & 0x1F);

                Gpt(thetaPtr);
            }

            _stages[tap25][0] = _stages[tap25][0] ^ _stages[_tap][2];
            _stages[tap25][1] = _stages[tap25][1] ^ _stages[_tap][3];
            _stages[tap25][2] = _stages[tap25][2] ^ _stages[_tap][4];
            _stages[tap25][3] = _stages[tap25][3] ^ _stages[_tap][5];
            _stages[tap25][4] = _stages[tap25][4] ^ _stages[_tap][6];
            _stages[tap25][5] = _stages[tap25][5] ^ _stages[_tap][7];
            _stages[tap25][6] = _stages[tap25][6] ^ _stages[_tap][0];
            _stages[tap25][7] = _stages[tap25][7] ^ _stages[_tap][1];
            _stages[_tap][0] = _stages[_tap][0] ^ buffer[0];
            _stages[_tap][1] = _stages[_tap][1] ^ buffer[1];
            _stages[_tap][2] = _stages[_tap][2] ^ buffer[2];
            _stages[_tap][3] = _stages[_tap][3] ^ buffer[3];
            _stages[_tap][4] = _stages[_tap][4] ^ buffer[4];
            _stages[_tap][5] = _stages[_tap][5] ^ buffer[5];
            _stages[_tap][6] = _stages[_tap][6] ^ buffer[6];
            _stages[_tap][7] = _stages[_tap][7] ^ buffer[7];

            _state[0] = _theta[0] ^ 0x01;
            _state[1] = _theta[1] ^ buffer[0];
            _state[2] = _theta[2] ^ buffer[1];
            _state[3] = _theta[3] ^ buffer[2];
            _state[4] = _theta[4] ^ buffer[3];
            _state[5] = _theta[5] ^ buffer[4];
            _state[6] = _theta[6] ^ buffer[5];
            _state[7] = _theta[7] ^ buffer[6];
            _state[8] = _theta[8] ^ buffer[7];
            _state[9] = _theta[9] ^ _stages[tap16][0];
            _state[10] = _theta[10] ^ _stages[tap16][1];
            _state[11] = _theta[11] ^ _stages[tap16][2];
            _state[12] = _theta[12] ^ _stages[tap16][3];
            _state[13] = _theta[13] ^ _stages[tap16][4];
            _state[14] = _theta[14] ^ _stages[tap16][5];
            _state[15] = _theta[15] ^ _stages[tap16][6];
            _state[16] = _theta[16] ^ _stages[tap16][7];
        }

        private unsafe void Gpt(uint* ptrTheta)
        {
            _gamma[0] = _state[0] ^ (_state[1] | ~_state[2]);
            _gamma[1] = _state[1] ^ (_state[2] | ~_state[3]);
            _gamma[2] = _state[2] ^ (_state[3] | ~_state[4]);
            _gamma[3] = _state[3] ^ (_state[4] | ~_state[5]);
            _gamma[4] = _state[4] ^ (_state[5] | ~_state[6]);
            _gamma[5] = _state[5] ^ (_state[6] | ~_state[7]);
            _gamma[6] = _state[6] ^ (_state[7] | ~_state[8]);
            _gamma[7] = _state[7] ^ (_state[8] | ~_state[9]);
            _gamma[8] = _state[8] ^ (_state[9] | ~_state[10]);
            _gamma[9] = _state[9] ^ (_state[10] | ~_state[11]);
            _gamma[10] = _state[10] ^ (_state[11] | ~_state[12]);
            _gamma[11] = _state[11] ^ (_state[12] | ~_state[13]);
            _gamma[12] = _state[12] ^ (_state[13] | ~_state[14]);
            _gamma[13] = _state[13] ^ (_state[14] | ~_state[15]);
            _gamma[14] = _state[14] ^ (_state[15] | ~_state[16]);
            _gamma[15] = _state[15] ^ (_state[16] | ~_state[0]);
            _gamma[16] = _state[16] ^ (_state[0] | ~_state[1]);

            _pi[0] = _gamma[0];
            _pi[1] = Bits.RotateLeft32(_gamma[7], 1);
            _pi[2] = Bits.RotateLeft32(_gamma[14], 3);
            _pi[3] = Bits.RotateLeft32(_gamma[4], 6);
            _pi[4] = Bits.RotateLeft32(_gamma[11], 10);
            _pi[5] = Bits.RotateLeft32(_gamma[1], 15);
            _pi[6] = Bits.RotateLeft32(_gamma[8], 21);
            _pi[7] = Bits.RotateLeft32(_gamma[15], 28);
            _pi[8] = Bits.RotateLeft32(_gamma[5], 4);
            _pi[9] = Bits.RotateLeft32(_gamma[12], 13);
            _pi[10] = Bits.RotateLeft32(_gamma[2], 23);
            _pi[11] = Bits.RotateLeft32(_gamma[9], 2);
            _pi[12] = Bits.RotateLeft32(_gamma[16], 14);
            _pi[13] = Bits.RotateLeft32(_gamma[6], 27);
            _pi[14] = Bits.RotateLeft32(_gamma[13], 9);
            _pi[15] = Bits.RotateLeft32(_gamma[3], 24);
            _pi[16] = Bits.RotateLeft32(_gamma[10], 8);

            ptrTheta[0] = _pi[0] ^ _pi[1] ^ _pi[4];
            ptrTheta[1] = _pi[1] ^ _pi[2] ^ _pi[5];
            ptrTheta[2] = _pi[2] ^ _pi[3] ^ _pi[6];
            ptrTheta[3] = _pi[3] ^ _pi[4] ^ _pi[7];
            ptrTheta[4] = _pi[4] ^ _pi[5] ^ _pi[8];
            ptrTheta[5] = _pi[5] ^ _pi[6] ^ _pi[9];
            ptrTheta[6] = _pi[6] ^ _pi[7] ^ _pi[10];
            ptrTheta[7] = _pi[7] ^ _pi[8] ^ _pi[11];
            ptrTheta[8] = _pi[8] ^ _pi[9] ^ _pi[12];
            ptrTheta[9] = _pi[9] ^ _pi[10] ^ _pi[13];
            ptrTheta[10] = _pi[10] ^ _pi[11] ^ _pi[14];
            ptrTheta[11] = _pi[11] ^ _pi[12] ^ _pi[15];
            ptrTheta[12] = _pi[12] ^ _pi[13] ^ _pi[16];
            ptrTheta[13] = _pi[13] ^ _pi[14] ^ _pi[0];
            ptrTheta[14] = _pi[14] ^ _pi[15] ^ _pi[1];
            ptrTheta[15] = _pi[15] ^ _pi[16] ^ _pi[2];
            ptrTheta[16] = _pi[16] ^ _pi[0] ^ _pi[3];
        }
    }
}