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
using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal abstract class SHA3 : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        internal enum HashMode
        {
            Keccak = 0x1,
            SHA3 = 0x6,
            Shake = 0x1F,
            CShake = 0x04
        }

        protected ulong[] State;

        private static readonly ulong[] Rc =
        {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
            0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

        protected SHA3(int hashSize)
            : base(hashSize, 200 - hashSize * 2)
        {
            State = new ulong[25];
        }

        protected virtual HashMode GetHashMode() => HashMode.SHA3;

        public override void Initialize()
        {
            ArrayUtils.ZeroFill(State);
            base.Initialize();
        }

        public override string Name => GetType().Name;

        protected void KeccakF1600StatePermute()
        {
            var aba = State[0];
            var abe = State[1];
            var abi = State[2];
            var abo = State[3];
            var abu = State[4];
            var aga = State[5];
            var age = State[6];
            var agi = State[7];
            var ago = State[8];
            var agu = State[9];
            var aka = State[10];
            var ake = State[11];
            var aki = State[12];
            var ako = State[13];
            var aku = State[14];
            var ama = State[15];
            var ame = State[16];
            var ami = State[17];
            var amo = State[18];
            var amu = State[19];
            var asa = State[20];
            var ase = State[21];
            var asi = State[22];
            var aso = State[23];
            var asu = State[24];

            var round = 0;
            while (round < 24)
            {
                var bca = aba ^ aga ^ aka ^ ama ^ asa;
                var bce = abe ^ age ^ ake ^ ame ^ ase;
                var bci = abi ^ agi ^ aki ^ ami ^ asi;
                var bco = abo ^ ago ^ ako ^ amo ^ aso;
                var bcu = abu ^ agu ^ aku ^ amu ^ asu;

                var a = bcu ^ Bits.RotateLeft64(bce, 1);
                var e = bca ^ Bits.RotateLeft64(bci, 1);
                var i = bce ^ Bits.RotateLeft64(bco, 1);
                var o = bci ^ Bits.RotateLeft64(bcu, 1);
                var u = bco ^ Bits.RotateLeft64(bca, 1);

                aba ^= a;
                bca = aba;
                age ^= e;
                bce = Bits.RotateLeft64(age, 44);
                aki ^= i;
                bci = Bits.RotateLeft64(aki, 43);
                amo ^= o;
                bco = Bits.RotateLeft64(amo, 21);
                asu ^= u;
                bcu = Bits.RotateLeft64(asu, 14);
                var eba = bca ^ (~bce & bci);
                eba ^= Rc[round];
                var ebe = bce ^ (~bci & bco);
                var ebi = bci ^ (~bco & bcu);
                var ebo = bco ^ (~bcu & bca);
                var ebu = bcu ^ (~bca & bce);

                abo ^= o;
                bca = Bits.RotateLeft64(abo, 28);
                agu ^= u;
                bce = Bits.RotateLeft64(agu, 20);
                aka ^= a;
                bci = Bits.RotateLeft64(aka, 3);
                ame ^= e;
                bco = Bits.RotateLeft64(ame, 45);
                asi ^= i;
                bcu = Bits.RotateLeft64(asi, 61);
                var ega = bca ^ (~bce & bci);
                var ege = bce ^ (~bci & bco);
                var egi = bci ^ (~bco & bcu);
                var ego = bco ^ (~bcu & bca);
                var egu = bcu ^ (~bca & bce);

                abe ^= e;
                bca = Bits.RotateLeft64(abe, 1);
                agi ^= i;
                bce = Bits.RotateLeft64(agi, 6);
                ako ^= o;
                bci = Bits.RotateLeft64(ako, 25);
                amu ^= u;
                bco = Bits.RotateLeft64(amu, 8);
                asa ^= a;
                bcu = Bits.RotateLeft64(asa, 18);
                var eka = bca ^ (~bce & bci);
                var eke = bce ^ (~bci & bco);
                var eki = bci ^ (~bco & bcu);
                var eko = bco ^ (~bcu & bca);
                var eku = bcu ^ (~bca & bce);

                abu ^= u;
                bca = Bits.RotateLeft64(abu, 27);
                aga ^= a;
                bce = Bits.RotateLeft64(aga, 36);
                ake ^= e;
                bci = Bits.RotateLeft64(ake, 10);
                ami ^= i;
                bco = Bits.RotateLeft64(ami, 15);
                aso ^= o;
                bcu = Bits.RotateLeft64(aso, 56);
                var ema = bca ^ (~bce & bci);
                var eme = bce ^ (~bci & bco);
                var emi = bci ^ (~bco & bcu);
                var emo = bco ^ (~bcu & bca);
                var emu = bcu ^ (~bca & bce);

                abi ^= i;
                bca = Bits.RotateLeft64(abi, 62);
                ago ^= o;
                bce = Bits.RotateLeft64(ago, 55);
                aku ^= u;
                bci = Bits.RotateLeft64(aku, 39);
                ama ^= a;
                bco = Bits.RotateLeft64(ama, 41);
                ase ^= e;
                bcu = Bits.RotateLeft64(ase, 2);
                var esa = bca ^ (~bce & bci);
                var ese = bce ^ (~bci & bco);
                var esi = bci ^ (~bco & bcu);
                var eso = bco ^ (~bcu & bca);
                var esu = bcu ^ (~bca & bce);

                bca = eba ^ ega ^ eka ^ ema ^ esa;
                bce = ebe ^ ege ^ eke ^ eme ^ ese;
                bci = ebi ^ egi ^ eki ^ emi ^ esi;
                bco = ebo ^ ego ^ eko ^ emo ^ eso;
                bcu = ebu ^ egu ^ eku ^ emu ^ esu;

                a = bcu ^ Bits.RotateLeft64(bce, 1);
                e = bca ^ Bits.RotateLeft64(bci, 1);
                i = bce ^ Bits.RotateLeft64(bco, 1);
                o = bci ^ Bits.RotateLeft64(bcu, 1);
                u = bco ^ Bits.RotateLeft64(bca, 1);

                eba ^= a;
                bca = eba;
                ege ^= e;
                bce = Bits.RotateLeft64(ege, 44);
                eki ^= i;
                bci = Bits.RotateLeft64(eki, 43);
                emo ^= o;
                bco = Bits.RotateLeft64(emo, 21);
                esu ^= u;
                bcu = Bits.RotateLeft64(esu, 14);
                aba = bca ^ (~bce & bci);
                aba ^= Rc[round + 1];
                abe = bce ^ (~bci & bco);
                abi = bci ^ (~bco & bcu);
                abo = bco ^ (~bcu & bca);
                abu = bcu ^ (~bca & bce);

                ebo ^= o;
                bca = Bits.RotateLeft64(ebo, 28);
                egu ^= u;
                bce = Bits.RotateLeft64(egu, 20);
                eka ^= a;
                bci = Bits.RotateLeft64(eka, 3);
                eme ^= e;
                bco = Bits.RotateLeft64(eme, 45);
                esi ^= i;
                bcu = Bits.RotateLeft64(esi, 61);
                aga = bca ^ (~bce & bci);
                age = bce ^ (~bci & bco);
                agi = bci ^ (~bco & bcu);
                ago = bco ^ (~bcu & bca);
                agu = bcu ^ (~bca & bce);

                ebe ^= e;
                bca = Bits.RotateLeft64(ebe, 1);
                egi ^= i;
                bce = Bits.RotateLeft64(egi, 6);
                eko ^= o;
                bci = Bits.RotateLeft64(eko, 25);
                emu ^= u;
                bco = Bits.RotateLeft64(emu, 8);
                esa ^= a;
                bcu = Bits.RotateLeft64(esa, 18);
                aka = bca ^ (~bce & bci);
                ake = bce ^ (~bci & bco);
                aki = bci ^ (~bco & bcu);
                ako = bco ^ (~bcu & bca);
                aku = bcu ^ (~bca & bce);

                ebu ^= u;
                bca = Bits.RotateLeft64(ebu, 27);
                ega ^= a;
                bce = Bits.RotateLeft64(ega, 36);
                eke ^= e;
                bci = Bits.RotateLeft64(eke, 10);
                emi ^= i;
                bco = Bits.RotateLeft64(emi, 15);
                eso ^= o;
                bcu = Bits.RotateLeft64(eso, 56);
                ama = bca ^ (~bce & bci);
                ame = bce ^ (~bci & bco);
                ami = bci ^ (~bco & bcu);
                amo = bco ^ (~bcu & bca);
                amu = bcu ^ (~bca & bce);

                ebi ^= i;
                bca = Bits.RotateLeft64(ebi, 62);
                ego ^= o;
                bce = Bits.RotateLeft64(ego, 55);
                eku ^= u;
                bci = Bits.RotateLeft64(eku, 39);
                ema ^= a;
                bco = Bits.RotateLeft64(ema, 41);
                ese ^= e;
                bcu = Bits.RotateLeft64(ese, 2);
                asa = bca ^ (~bce & bci);
                ase = bce ^ (~bci & bco);
                asi = bci ^ (~bco & bcu);
                aso = bco ^ (~bcu & bca);
                asu = bcu ^ (~bca & bce);

                round += 2;
            }

            State[0] = aba;
            State[1] = abe;
            State[2] = abi;
            State[3] = abo;
            State[4] = abu;
            State[5] = aga;
            State[6] = age;
            State[7] = agi;
            State[8] = ago;
            State[9] = agu;
            State[10] = aka;
            State[11] = ake;
            State[12] = aki;
            State[13] = ako;
            State[14] = aku;
            State[15] = ama;
            State[16] = ame;
            State[17] = ami;
            State[18] = amo;
            State[19] = amu;
            State[20] = asa;
            State[21] = ase;
            State[22] = asi;
            State[23] = aso;
            State[24] = asu;
        }

        protected override unsafe void Finish()
        {
            var bufferPos = Buffer.Position;

            var block = Buffer.GetBytesZeroPadded();

            block[bufferPos] = (byte)GetHashMode();
            block[BlockSize - 1] = (byte)(block[BlockSize - 1] ^ 0x80);

            fixed (byte* blockPtr = block)
            {
                TransformBlock(blockPtr, block.Length, 0);
            }
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (ulong* statePtr = State)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le64_copy(statePtr, 0, resultPtr, 0, result.Length);
                }
            }

            return result;
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc ulong[21];

            Converters.le64_copy(data, index, buffer, 0, dataLength);

            var j = 0;
            var blockCount = BlockSize >> 3;
            while (j < blockCount)
            {
                State[j] = State[j] ^ buffer[j];
                j++;
            }

            KeccakF1600StatePermute();
        }
    }

    internal sealed class SHA3_224 : SHA3
    {
        internal SHA3_224() :
            base((int)Enum.HashSize.HashSize224)
        {
        }

        public override IHash Clone() =>
            new SHA3_224
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal sealed class SHA3_256 : SHA3
    {
        internal SHA3_256() :
            base((int)Enum.HashSize.HashSize256)
        {
        }

        public override IHash Clone() =>
            new SHA3_256
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal sealed class SHA3_384 : SHA3
    {
        internal SHA3_384() :
            base((int)Enum.HashSize.HashSize384)
        {
        }

        public override IHash Clone() =>
            new SHA3_384
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal sealed class SHA3_512 : SHA3
    {
        internal SHA3_512() :
            base((int)Enum.HashSize.HashSize512)
        {
        }

        public override IHash Clone() =>
            new SHA3_512
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal abstract class Keccak : SHA3
    {
        protected override HashMode GetHashMode() => HashMode.Keccak;

        protected Keccak(int hashSize) : base(hashSize)
        {
        }
    }

    internal sealed class Keccak_224 : Keccak
    {
        internal Keccak_224() :
            base((int)Enum.HashSize.HashSize224)
        {
        }

        public override IHash Clone() =>
            new Keccak_224
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal sealed class Keccak_256 : Keccak
    {
        internal Keccak_256() :
            base((int)Enum.HashSize.HashSize256)
        {
        }

        public override IHash Clone() =>
            new Keccak_256
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal sealed class Keccak_288 : Keccak
    {
        internal Keccak_288() :
            base((int)Enum.HashSize.HashSize288)
        {
        }

        public override IHash Clone() =>
            new Keccak_288
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal sealed class Keccak_384 : Keccak
    {
        internal Keccak_384() :
            base((int)Enum.HashSize.HashSize384)
        {
        }

        public override IHash Clone() =>
            new Keccak_384
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal sealed class Keccak_512 : Keccak
    {
        internal Keccak_512() :
            base((int)Enum.HashSize.HashSize512)
        {
        }

        public override IHash Clone() =>
            new Keccak_512
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };
    }

    internal abstract class Shake : SHA3, IXOF
    {
        private const string InvalidXofSize = "XofSizeInBits must be multiples of 8 & be greater than 0";
        private const string OutputLengthOverflow = "Output length is above the digest length";
        private const string WriteToXofAfterRead = "'{0}' Write to Xof after read not allowed";

        private ulong _xofSizeInBits;

        protected ulong BufferPosition, DigestPosition;
        protected byte[] ShakeBuffer;
        protected bool Finalized;

        protected Shake(int hashSize) :
            base(hashSize)
        {
            ShakeBuffer = new byte[8];
        }

        protected override HashMode GetHashMode() => HashMode.Shake;

        public override void Initialize()
        {
            BufferPosition = 0;
            DigestPosition = 0;
            Finalized = false;
            ArrayUtils.ZeroFill(ShakeBuffer);
            base.Initialize();
        }

        public override IHashResult TransformFinal()
        {
            var buffer = GetResult();
            Debug.Assert((ulong)buffer.Length == XofSizeInBits >> 3);
            Initialize();

            return new HashResult(buffer);
        }

        protected override byte[] GetResult()
        {
            var xofSizeInBytes = (int)(XofSizeInBits >> 3);

            var result = new byte[xofSizeInBytes];

            DoOutput(result, 0, xofSizeInBytes);

            return result;
        }

        private void SetXofSizeInBitsInternal(ulong xofSizeInBits)
        {
            var xofSizeInBytes = xofSizeInBits >> 3;

            if ((xofSizeInBits & 0x07) != 0 || xofSizeInBytes < 1)
                throw new ArgumentException(InvalidXofSize);

            _xofSizeInBits = xofSizeInBits;
        }

        public virtual ulong XofSizeInBits
        {
            get => _xofSizeInBits;
            set => SetXofSizeInBitsInternal(value);
        }

        public unsafe void DoOutput(Span<byte> dest)
        {
            if (dest == null) throw new ArgumentNullException(nameof(dest));

            var outputLength = dest.Length;
            var destOffset = 0;

            if (DigestPosition + (ulong) outputLength > XofSizeInBits >> 3)
                throw new ArgumentException(OutputLengthOverflow);

            if (!Finalized)
            {
                Finish();
                Finalized = true;
            }

            while (outputLength > 0)
            {
                if ((DigestPosition & 7) == 0)
                {
                    if (BufferPosition * 8 >= (ulong)BlockSize)
                    {
                        KeccakF1600StatePermute();
                        BufferPosition = 0;
                    }

                    Converters.ReadUInt64AsBytesLE(State[BufferPosition], ShakeBuffer, 0);

                    BufferPosition++;
                }

                var blockOffset = (int)(DigestPosition & 7);
                var diff = ShakeBuffer.Length - blockOffset;
                var count = Math.Min(outputLength, diff);

                fixed (byte* destPtr = &dest[destOffset], srcPtr = &ShakeBuffer[blockOffset])
                {
                    PointerUtils.MemMove(destPtr, srcPtr, count);
                }

                outputLength -= count;
                destOffset += count;
                DigestPosition += (ulong) count;
            }
        }

        private void DoOutput(byte[] dest, int destOffset,
            int outputLength)
        {
            DoOutput(dest.AsSpan().Slice(destOffset, outputLength));
        }
        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (Finalized)
                throw new InvalidOperationException(
                    string.Format(WriteToXofAfterRead, Name));

            base.TransformByteSpan(data);
        }
    }

    internal sealed class Shake_128 : Shake
    {
        internal Shake_128() :
            base((int)Enum.HashSize.HashSize128)
        {
        }

        public override IHash Clone() =>
            new Shake_128
            {
                // Internal Sha3 Cloning
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                // Shake_128 Cloning
                BufferPosition = BufferPosition,
                DigestPosition = DigestPosition,
                Finalized = Finalized,
                ShakeBuffer = ArrayUtils.Clone(ShakeBuffer),
                // Xof Cloning
                XofSizeInBits = XofSizeInBits
            };
    }

    internal sealed class Shake_256 : Shake
    {
        internal Shake_256() :
            base((int)Enum.HashSize.HashSize256)
        {
        }

        public override IHash Clone() =>
            new Shake_256
            {
                // Internal Sha3 Cloning
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                // Shake_256 Cloning
                BufferPosition = BufferPosition,
                DigestPosition = DigestPosition,
                Finalized = Finalized,
                ShakeBuffer = ArrayUtils.Clone(ShakeBuffer),
                // Xof Cloning
                XofSizeInBits = XofSizeInBits
            };
    }

    internal abstract class CShake : Shake
    {
        protected readonly byte[] N, S;
        protected byte[] InitBlock;

        /// <param name="hashSize">
        /// the hashSize of the underlying Shake function
        /// </param>
        /// <param name="n">
        /// the function name string, note this is reserved for use by NIST.
        /// Avoid using if not required
        /// </param>
        /// <param name="s">
        /// the customization string - available for local use
        /// </param>
        protected CShake(int hashSize, byte[] n, byte[] s)
            : base(hashSize)
        {
            if (n == null) throw new ArgumentNullException(nameof(n));
            if (s == null) throw new ArgumentNullException(nameof(s));

            N = ArrayUtils.Clone(n);
            S = ArrayUtils.Clone(s);

            InitBlock = N.Length == 0 && S.Length == 0
                ? new byte[0]
                : ArrayUtils.Concatenate(EncodeString(N), EncodeString(S));
        }

        protected override HashMode GetHashMode() => N.Length == 0 && S.Length == 0 ? HashMode.Shake : HashMode.CShake;

        // LeftEncode returns max 9 bytes
        private static byte[] LeftEncode(ulong input)
        {
            int idx;

            byte n = 1;
            var v = input;
            v >>= 8;

            while (v != 0)
            {
                n++;
                v >>= 8;
            }

            var result = new byte[n + 1];
            result[0] = n;

            for (idx = 1; idx <= n; idx++)
                result[idx] = (byte)(input >> (8 * (n - idx)));

            return result;
        }

        public override void Initialize()
        {
            base.Initialize();
            if (InitBlock.Length > 0)
                TransformByteSpan(BytePad(InitBlock, BlockSize));
        }

        public static byte[] RightEncode(ulong input)
        {
            int idx;

            byte n = 1;
            var v = input;
            v >>= 8;

            while (v != 0)
            {
                n++;
                v >>= 8;
            }

            var result = new byte[n + 1];
            result[n] = n;

            for (idx = 1; idx <= n; idx++)
                result[idx - 1] = (byte)(input >> (8 * (n - idx)));

            return result;
        }

        public static byte[] BytePad(byte[] input, int w)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            var buffer = ArrayUtils.Concatenate(LeftEncode((ulong)w), input);
            var padLength = w - buffer.Length % w;
            return ArrayUtils.Concatenate(buffer, new byte[padLength]);
        }

        public static byte[] EncodeString(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return input.Length == 0
                ? LeftEncode(0)
                : ArrayUtils.Concatenate(LeftEncode((ulong)input.Length * 8), input);
        }
    }

    internal sealed class CShake_128 : CShake
    {
        internal CShake_128(byte[] n, byte[] s) :
            base((int)Enum.HashSize.HashSize128, n, s)
        {
        }

        public override IHash Clone() =>
            new CShake_128(N, S)
            {
                // Internal Sha3 Cloning
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                // CShake_128 Cloning
                InitBlock = ArrayUtils.Clone(InitBlock),
                BufferPosition = BufferPosition,
                DigestPosition = DigestPosition,
                Finalized = Finalized,
                ShakeBuffer = ArrayUtils.Clone(ShakeBuffer),
                // Xof Cloning
                XofSizeInBits = XofSizeInBits
            };
    }

    internal sealed class CShake_256 : CShake
    {
        internal CShake_256(byte[] n, byte[] s) :
            base((int)Enum.HashSize.HashSize256, n, s)
        {
        }

        public override IHash Clone() =>
            new CShake_256(N, S)
            {
                // Internal Sha3 Cloning
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                // CShake_256 Cloning
                InitBlock = ArrayUtils.Clone(InitBlock),
                BufferPosition = BufferPosition,
                DigestPosition = DigestPosition,
                Finalized = Finalized,
                ShakeBuffer = ArrayUtils.Clone(ShakeBuffer),
                // Xof Cloning
                XofSizeInBits = XofSizeInBits
            };
    }
}