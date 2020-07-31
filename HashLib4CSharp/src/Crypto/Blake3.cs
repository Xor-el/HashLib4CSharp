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
using System.Runtime.CompilerServices;
using HashLib4CSharp.Base;
using HashLib4CSharp.Enum;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal class Blake3 : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        private const string MaximumOutputLengthExceeded = "Maximum output length is 2^64 bytes";
        private const string InvalidKeyLength = "Key length Must not be greater than {0}, '{1}'";

        private const int ChunkSize = 1024;
        private const int BlockSizeInBytes = 64;

        private const uint flagChunkStart = 1 << 0;
        private const uint flagChunkEnd = 1 << 1;
        private const uint flagParent = 1 << 2;
        private const uint flagRoot = 1 << 3;
        private const uint flagKeyedHash = 1 << 4;

        // maximum size in bytes this digest output reader can produce
        private const ulong MaxDigestLengthInBytes = ulong.MaxValue;

        internal const int KeyLengthInBytes = 32;

        internal static readonly uint[] IV =
        {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };

        protected Blake3ChunkState ChunkState;
        protected Blake3OutputReader OutputReader;
        protected uint[] Key;
        protected uint Flags;

        // log(n) set of Merkle subtree roots, at most one per height.
        // stack [54][8]uint32
        protected uint[][] Stack; // 2^54 * chunkSize = 2^64

        // bit vector indicating which stack elems are valid; also number of chunks added
        protected ulong Used;

        // A Blake3Node represents a chunk or parent in the BLAKE3 Merkle tree. In BLAKE3
        // terminology, the elements of the bottom layer (aka "leaves") of the tree are
        // called chunk nodes, and the elements of upper layers (aka "interior nodes")
        // are called parent nodes.
        //
        // Computing a BLAKE3 hash involves splitting the input into chunk nodes, then
        // repeatedly merging these nodes into parent nodes, until only a single "root"
        // node remains. The root node can then be used to generate up to 2^64 - 1 bytes
        // of pseudorandom output.
        // protected sealed class Blake3Node
        protected unsafe struct Blake3Node
        {
            // the chaining value from the previous state
            public fixed uint CV[8];
            // the current state
            public fixed uint Block[16];
            public ulong Counter;
            public uint BlockLen, Flags;

            public Blake3Node Clone()
            {
                var result = DefaultBlake3Node();
                fixed (uint* ptrCV = CV, ptrBlock = Block)
                {
                    PointerUtils.MemMove(result.CV, ptrCV, 8 * sizeof(uint));
                    PointerUtils.MemMove(result.Block, ptrBlock, 16 * sizeof(uint));
                }

                result.Counter = Counter;
                result.BlockLen = BlockLen;
                result.Flags = Flags;
                return result;
            }

            // ChainingValue returns the first 8 words of the compressed node. This is used
            // in two places. First, when a chunk node is being constructed, its cv is
            // overwritten with this value after each block of input is processed. Second,
            // when two nodes are merged into a parent, each of their chaining values
            // supplies half of the new node's block.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void ChainingValue(uint* result)
            {
                var full = stackalloc uint[16];
                CompressWithHalfFinalization(full);
                PointerUtils.MemMove(&result[0], full, 8 * sizeof(uint));
            }

            private void Mixing(uint* state)
            {
                // initializes state here
                state[0] = CV[0];
                state[1] = CV[1];
                state[2] = CV[2];
                state[3] = CV[3];
                state[4] = CV[4];
                state[5] = CV[5];
                state[6] = CV[6];
                state[7] = CV[7];
                state[8] = IV[0];
                state[9] = IV[1];
                state[10] = IV[2];
                state[11] = IV[3];
                state[12] = (uint)Counter;
                state[13] = (uint)(Counter >> 32);
                state[14] = BlockLen;
                state[15] = Flags;

                // NOTE: we unroll all of the rounds, as well as the permutations that occur
                // between rounds.
                // Round 0
                // Mix the columns.
                G(state, 0, 4, 8, 12, Block[0], Block[1]);
                G(state, 1, 5, 9, 13, Block[2], Block[3]);
                G(state, 2, 6, 10, 14, Block[4], Block[5]);
                G(state, 3, 7, 11, 15, Block[6], Block[7]);

                // Mix the rows.
                G(state, 0, 5, 10, 15, Block[8], Block[9]);
                G(state, 1, 6, 11, 12, Block[10], Block[11]);
                G(state, 2, 7, 8, 13, Block[12], Block[13]);
                G(state, 3, 4, 9, 14, Block[14], Block[15]);

                // Round 1
                // Mix the columns.
                G(state, 0, 4, 8, 12, Block[2], Block[6]);
                G(state, 1, 5, 9, 13, Block[3], Block[10]);
                G(state, 2, 6, 10, 14, Block[7], Block[0]);
                G(state, 3, 7, 11, 15, Block[4], Block[13]);

                // Mix the rows.
                G(state, 0, 5, 10, 15, Block[1], Block[11]);
                G(state, 1, 6, 11, 12, Block[12], Block[5]);
                G(state, 2, 7, 8, 13, Block[9], Block[14]);
                G(state, 3, 4, 9, 14, Block[15], Block[8]);

                // Round 2
                // Mix the columns.
                G(state, 0, 4, 8, 12, Block[3], Block[4]);
                G(state, 1, 5, 9, 13, Block[10], Block[12]);
                G(state, 2, 6, 10, 14, Block[13], Block[2]);
                G(state, 3, 7, 11, 15, Block[7], Block[14]);

                // Mix the rows.
                G(state, 0, 5, 10, 15, Block[6], Block[5]);
                G(state, 1, 6, 11, 12, Block[9], Block[0]);
                G(state, 2, 7, 8, 13, Block[11], Block[15]);
                G(state, 3, 4, 9, 14, Block[8], Block[1]);

                // Round 3
                // Mix the columns.
                G(state, 0, 4, 8, 12, Block[10], Block[7]);
                G(state, 1, 5, 9, 13, Block[12], Block[9]);
                G(state, 2, 6, 10, 14, Block[14], Block[3]);
                G(state, 3, 7, 11, 15, Block[13], Block[15]);

                // Mix the rows.
                G(state, 0, 5, 10, 15, Block[4], Block[0]);
                G(state, 1, 6, 11, 12, Block[11], Block[2]);
                G(state, 2, 7, 8, 13, Block[5], Block[8]);
                G(state, 3, 4, 9, 14, Block[1], Block[6]);

                // Round 4
                // Mix the columns.
                G(state, 0, 4, 8, 12, Block[12], Block[13]);
                G(state, 1, 5, 9, 13, Block[9], Block[11]);
                G(state, 2, 6, 10, 14, Block[15], Block[10]);
                G(state, 3, 7, 11, 15, Block[14], Block[8]);

                // Mix the rows.
                G(state, 0, 5, 10, 15, Block[7], Block[2]);
                G(state, 1, 6, 11, 12, Block[5], Block[3]);
                G(state, 2, 7, 8, 13, Block[0], Block[1]);
                G(state, 3, 4, 9, 14, Block[6], Block[4]);

                // Round 5
                // Mix the columns.
                G(state, 0, 4, 8, 12, Block[9], Block[14]);
                G(state, 1, 5, 9, 13, Block[11], Block[5]);
                G(state, 2, 6, 10, 14, Block[8], Block[12]);
                G(state, 3, 7, 11, 15, Block[15], Block[1]);

                // Mix the rows.
                G(state, 0, 5, 10, 15, Block[13], Block[3]);
                G(state, 1, 6, 11, 12, Block[0], Block[10]);
                G(state, 2, 7, 8, 13, Block[2], Block[6]);
                G(state, 3, 4, 9, 14, Block[4], Block[7]);

                // Round 6
                // Mix the columns.
                G(state, 0, 4, 8, 12, Block[11], Block[15]);
                G(state, 1, 5, 9, 13, Block[5], Block[0]);
                G(state, 2, 6, 10, 14, Block[1], Block[9]);
                G(state, 3, 7, 11, 15, Block[8], Block[6]);

                // Mix the rows.
                G(state, 0, 5, 10, 15, Block[14], Block[10]);
                G(state, 1, 6, 11, 12, Block[2], Block[12]);
                G(state, 2, 7, 8, 13, Block[3], Block[4]);
                G(state, 3, 4, 9, 14, Block[7], Block[13]);
            }

            // compress is the core hash function, generating 16 pseudorandom words from a
            // node.
            // NOTE: we unroll all of the rounds, as well as the permutations that occur
            // between rounds.
            public void CompressWithFullFinalization(uint* state)
            {
                Mixing(state);
                // compression finalization
                state[0] = state[0] ^ state[8];
                state[1] = state[1] ^ state[9];
                state[2] = state[2] ^ state[10];
                state[3] = state[3] ^ state[11];
                state[4] = state[4] ^ state[12];
                state[5] = state[5] ^ state[13];
                state[6] = state[6] ^ state[14];
                state[7] = state[7] ^ state[15];
                state[8] = state[8] ^ CV[0];
                state[9] = state[9] ^ CV[1];
                state[10] = state[10] ^ CV[2];
                state[11] = state[11] ^ CV[3];
                state[12] = state[12] ^ CV[4];
                state[13] = state[13] ^ CV[5];
                state[14] = state[14] ^ CV[6];
                state[15] = state[15] ^ CV[7];
            }

            private void CompressWithHalfFinalization(uint* state)
            {
                Mixing(state);
                // compression finalization
                state[0] = state[0] ^ state[8];
                state[1] = state[1] ^ state[9];
                state[2] = state[2] ^ state[10];
                state[3] = state[3] ^ state[11];
                state[4] = state[4] ^ state[12];
                state[5] = state[5] ^ state[13];
                state[6] = state[6] ^ state[14];
                state[7] = state[7] ^ state[15];
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void G(uint* state, uint a, uint b, uint c, uint d, uint x, uint y)
            {
                var aa = state[a];
                var bb = state[b];
                var cc = state[c];
                var dd = state[d];

                aa = aa + bb + x;
                dd = Bits.RotateRight32(dd ^ aa, 16);
                cc += dd;
                bb = Bits.RotateRight32(bb ^ cc, 12);
                aa = aa + bb + y;
                dd = Bits.RotateRight32(dd ^ aa, 8);
                cc += dd;
                bb = Bits.RotateRight32(bb ^ cc, 7);

                state[a] = aa;
                state[b] = bb;
                state[c] = cc;
                state[d] = dd;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static Blake3Node CreateBlake3Node(uint[] cv, uint[] block,
                ulong counter, uint blockLen, uint flags)
            {
                var result = DefaultBlake3Node();
                fixed (uint* ptrCV = cv, ptrBlock = block)
                {
                    PointerUtils.MemMove(result.CV, ptrCV, 8 * sizeof(uint));
                    PointerUtils.MemMove(result.Block, ptrBlock, 16 * sizeof(uint));
                }

                result.Counter = counter;
                result.BlockLen = blockLen;
                result.Flags = flags;
                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static Blake3Node ParentNode(uint[] left, uint[] right, uint[] key, uint flags) =>
                CreateBlake3Node(key, ArrayUtils.Concatenate(left, right), 0, BlockSizeInBytes, flags | flagParent);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            internal static Blake3Node DefaultBlake3Node() => default;
        }

        // Blake3ChunkState manages the state involved in hashing a single chunk of input.
        protected unsafe struct Blake3ChunkState
        {
            private Blake3Node _n;
            private fixed byte _block[BlockSizeInBytes];
            private int _blockLen;
            public int BytesConsumed;

            public Blake3ChunkState Clone()
            {
                var result = DefaultBlake3ChunkState();
                fixed (byte* ptrBlock = _block)
                {
                    PointerUtils.MemMove(result._block, ptrBlock, BlockSizeInBytes);
                }

                result._n = _n.Clone();
                result._blockLen = _blockLen;
                result.BytesConsumed = BytesConsumed;
                return result;
            }

            // ChunkCounter is the index of this chunk, i.e. the number of chunks that have
            // been processed prior to this one.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public ulong ChunkCounter() => _n.Counter;

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public bool Complete() => BytesConsumed == ChunkSize;

            // node returns a node containing the chunkState's current state, with the
            // ChunkEnd flag set.
            public Blake3Node Node()
            {
                var result = _n.Clone();

                fixed (byte* blockPtr = _block)
                {
                    // pad the remaining space in the block with zeros
                    PointerUtils.MemSet(blockPtr + _blockLen, 0, BlockSizeInBytes - _blockLen);
                    Converters.le32_copy(blockPtr, 0, result.Block, 0, BlockSizeInBytes);
                }

                result.BlockLen = (uint)_blockLen;
                result.Flags |= flagChunkEnd;

                return result;
            }

            // update incorporates input into the chunkState.
            public void Update(byte* dataPtr, int dataLength)
            {
                var index = 0;

                fixed (byte* blockPtr = _block)
                {
                    fixed (uint* blockPtr2 = _n.Block)
                    {
                        fixed (uint* cvPtr = _n.CV)
                        {
                            while (dataLength > 0)
                            {
                                // If the block buffer is full, compress it and clear it. More
                                // input is coming, so this compression is not flagChunkEnd.
                                if (_blockLen == BlockSizeInBytes)
                                {
                                    // copy the chunk block (bytes) into the node block and chain it.
                                    Converters.le32_copy(blockPtr, 0, blockPtr2, 0,
                                        BlockSizeInBytes);
                                    _n.ChainingValue(cvPtr);
                                    // clear the start flag for all but the first block
                                    _n.Flags &= _n.Flags ^ flagChunkStart;
                                    _blockLen = 0;
                                }

                                // Copy input bytes into the chunk block.
                                var count = Math.Min(BlockSizeInBytes - _blockLen, dataLength);
                                PointerUtils.MemMove(blockPtr + _blockLen, dataPtr + index, count);

                                _blockLen += count;
                                BytesConsumed += count;
                                index += count;
                                dataLength -= count;
                            }
                        }
                    }
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static Blake3ChunkState CreateBlake3ChunkState(uint[] iv, ulong chunkCounter, uint flags)
            {
                var result = new Blake3ChunkState
                {
                    _n =
                    {
                        Counter = chunkCounter,
                        BlockLen = BlockSizeInBytes,
                        // compress the first block with the start flag set
                        Flags = flags | flagChunkStart
                    }
                };
                fixed (uint* ptrSrc = iv)
                {
                    PointerUtils.MemMove(result._n.CV, ptrSrc, 8 * sizeof(uint));
                }

                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static Blake3ChunkState DefaultBlake3ChunkState() => default;

        }

        protected unsafe struct Blake3OutputReader
        {
            private fixed byte _block[BlockSizeInBytes];
            public Blake3Node N;
            public ulong Offset;

            public Blake3OutputReader Clone()
            {
                var result = DefaultBlake3OutputReader();
                result.N = N.Clone();
                fixed (byte* ptrBlock = _block)
                {
                    PointerUtils.MemMove(result._block, ptrBlock, BlockSizeInBytes);
                }

                result.Offset = Offset;
                return result;
            }

            public void Read(Span<byte> dest)
            {
                var words = stackalloc uint[16];

                var outputLength = (ulong)dest.Length;
                var destOffset = 0;

                if (Offset == MaxDigestLengthInBytes)
                    throw new ArgumentException(MaximumOutputLengthExceeded);
                var remainder = MaxDigestLengthInBytes - Offset;
                outputLength = Math.Min(outputLength, remainder);

                fixed (byte* blockPtr = _block, destPtr = dest)
                {
                    while (outputLength > 0)
                    {
                        if ((Offset & (BlockSizeInBytes - 1)) == 0)
                        {
                            N.Counter = Offset / BlockSizeInBytes;
                            N.CompressWithFullFinalization(words);
                            Converters.le32_copy(words, 0, blockPtr, 0, BlockSizeInBytes);
                        }

                        var blockOffset = Offset & (BlockSizeInBytes - 1);

                        var diff = BlockSizeInBytes - blockOffset;

                        var count = (int)Math.Min(outputLength, diff);

                        PointerUtils.MemMove(destPtr + destOffset, blockPtr + blockOffset, count);

                        outputLength -= (ulong)count;
                        destOffset += count;
                        Offset += (ulong)count;
                    }
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            internal static Blake3OutputReader DefaultBlake3OutputReader() => default;
        }

        private unsafe Blake3Node RootNode()
        {
            var result = ChunkState.Node();
            var temp = new uint[8];

            var trailingZeros64 = TrailingZeros64(Used);
            var len64 = Len64(Used);

            fixed (uint* ptrTemp = temp)
            {
                int idx;
                for (idx = trailingZeros64; idx < len64; idx++)
                {
                    if (!HasSubTreeAtHeight(idx)) continue;
                    result.ChainingValue(ptrTemp);
                    result = Blake3Node.ParentNode(Stack[idx], temp, Key, Flags);
                }
            }

            result.Flags |= flagRoot;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool HasSubTreeAtHeight(int idx) => (Used & ((uint)1 << idx)) != 0;

        // AddChunkChainingValue appends a chunk to the right edge of the Merkle tree.
        private unsafe void AddChunkChainingValue(uint[] cv)
        {
            // seek to first open stack slot, merging subtrees as we go
            var idx = 0;
            fixed (uint* cvPtr = cv)
            {
                while (HasSubTreeAtHeight(idx))
                {
                    Blake3Node.ParentNode(Stack[idx], cv, Key, Flags).ChainingValue(cvPtr);
                    idx++;
                }
            }

            Stack[idx] = ArrayUtils.Clone(cv);
            Used++;
        }

        private static byte Len8(byte value)
        {
            byte result = 0;
            while (value != 0)
            {
                value = (byte)(value >> 1);
                result++;
            }

            return result;
        }

        // Len64 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
        private static int Len64(ulong value)
        {
            var result = 0;
            if (value >= 1)
            {
                value >>= 32;
                result = 32;
            }

            if (value >= 1 << 16)
            {
                value >>= 16;
                result += 16;
            }

            if (value < 1 << 8) return result + Len8((byte)value);
            value >>= 8;
            result += 8;

            return result + Len8((byte)value);
        }

        private static int TrailingZeros64(ulong value)
        {
            if (value == 0) return 64;

            var result = 0;
            while ((value & 1) == 0)
            {
                value >>= 1;
                result++;
            }

            return result;
        }

        public override string Name => $"{GetType().Name}_{HashSize * 8}";

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected void InternalDoOutput(Span<byte> dest) =>
            OutputReader.Read(dest);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected void Finish() => OutputReader.N = RootNode();

        private static unsafe uint[] InternalSetup(byte[] key)
        {
            if (key.Length == 0)
            {
                return ArrayUtils.Clone(IV);
            }

            var keyLength = key.Length;
            var result = new uint[8];
            if (keyLength != KeyLengthInBytes)
                throw new ArgumentException(
                    string.Format(InvalidKeyLength, KeyLengthInBytes, keyLength));

            fixed (byte* keyPtr = key)
            {
                fixed (uint* resultPtr = result)
                {
                    Converters.le32_copy(keyPtr, 0, resultPtr, 0, keyLength);
                }
            }

            return result;
        }

        internal Blake3(int hashSize, uint[] keyWords, uint flags)
            : base(hashSize, BlockSizeInBytes)
        {
            Key = ArrayUtils.Clone(keyWords);
            Flags = flags;

            Stack = new uint[54][];
            for (var idx = 0; idx < Stack.Length; idx++)
                Stack[idx] = new uint[8];
        }

        protected Blake3(int hashSize, byte[] key) : this(hashSize,
            key != null ? InternalSetup(key) : throw new ArgumentNullException(nameof(key)),
            key.Length == 0 ? 0 : flagKeyedHash)
        {
        }

        internal Blake3(HashSize hashSize, byte[] key) : this((int)hashSize,
            key ?? throw new ArgumentNullException(nameof(key)))
        {
        }

        public override void Initialize()
        {
            ChunkState = Blake3ChunkState.CreateBlake3ChunkState(Key, 0, Flags);
            OutputReader = Blake3OutputReader.DefaultBlake3OutputReader();
            ArrayUtils.ZeroFill(Stack);
            Used = 0;
        }

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var chainingValue = new uint[8];

            var length = data.Length;

            fixed (uint* chainingValuePtr = chainingValue)
            {
                fixed (byte* dataPtr = data)
                {
                    var dataPtr2 = dataPtr;

                    while (length > 0)
                    {
                        // If the current chunk is complete, finalize it and add it to the tree,
                        // then reset the chunk state (but keep incrementing the counter across
                        // chunks).
                        if (ChunkState.Complete())
                        {
                            ChunkState.Node().ChainingValue(chainingValuePtr);
                            AddChunkChainingValue(chainingValue);
                            ChunkState =
                                Blake3ChunkState.CreateBlake3ChunkState(Key, ChunkState.ChunkCounter() + 1, Flags);
                        }

                        // Compress input bytes into the current chunk state.
                        var count = Math.Min(ChunkSize - ChunkState.BytesConsumed, length);
                        ChunkState.Update(dataPtr2, count);

                        dataPtr2 += count;
                        length -= count;
                    }
                }
            }
        }

        public override IHashResult TransformFinal()
        {
            Finish();

            var buffer = new byte[HashSize];

            InternalDoOutput(buffer.AsSpan());

            IHashResult result = new HashResult(buffer);

            Initialize();

            return result;
        }

        public override IHash Clone() =>
            new Blake3(HashSize, Key, Flags)
            {
                ChunkState = ChunkState.Clone(),
                OutputReader = OutputReader.Clone(),
                Stack = ArrayUtils.Clone(Stack),
                Used = Used,
                BufferSize = BufferSize
            };
    }

    internal sealed class Blake3XOF : Blake3, IXOF
    {
        private const string InvalidXofSize = "XOFSizeInBits must be multiples of 8 and be greater than zero bytes";
        private const string InvalidOutputLength = "Output length is above the digest length";
        private const string WriteToXofAfterReadError = "'{0}' write to Xof after read not allowed";

        private bool _finalized;
        private ulong _xofSizeInBits;

        public ulong XofSizeInBits
        {
            get => _xofSizeInBits;
            set => SetXofSizeInBitsInternal(value);
        }

        internal Blake3XOF(int hashSize, byte[] key) : base(hashSize, key)
        {
        }

        internal Blake3XOF(int hashSize, uint[] keyWords, uint flags)
            : base(hashSize, keyWords, flags)
        {
        }

        public override string Name => GetType().Name;

        public override void Initialize()
        {
            _finalized = false;
            base.Initialize();
        }

        public override IHash Clone() =>
            new Blake3XOF(HashSize, new byte[0])
            {
                // Blake3 Cloning
                ChunkState = ChunkState.Clone(),
                OutputReader = OutputReader.Clone(),
                Stack = ArrayUtils.Clone(Stack),
                Used = Used,
                Flags = Flags,
                Key = ArrayUtils.Clone(Key),
                BufferSize = BufferSize,
                // Blake3XOF Cloning
                _finalized = _finalized,
                // Xof Cloning
                XofSizeInBits = XofSizeInBits
            };

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (_finalized)
                throw new InvalidOperationException(
                    string.Format(WriteToXofAfterReadError, Name));

            base.TransformByteSpan(data);
        }

        public override IHashResult TransformFinal()
        {
            var buffer = GetResult();
            Debug.Assert((ulong)buffer.Length == XofSizeInBits >> 3);
            Initialize();

            var result = new HashResult(buffer);

            return result;
        }

        public void DoOutput(Span<byte> dest)
        {
            if (dest == null) throw new ArgumentNullException(nameof(dest));

            var outputLength = dest.Length;

            if (OutputReader.Offset + (ulong)outputLength > XofSizeInBits >> 3)
                throw new ArgumentException(InvalidOutputLength);

            if (!_finalized)
            {
                Finish();
                _finalized = true;
            }

            InternalDoOutput(dest);
        }

        private void DoOutput(byte[] dest, int destOffset, int outputLength)
        {
            DoOutput(dest.AsSpan().Slice(destOffset, outputLength));
        }

        private void SetXofSizeInBitsInternal(ulong xofSizeInBits)
        {
            var xofSizeInBytes = xofSizeInBits >> 3;
            if ((xofSizeInBits & 0x7) != 0 || xofSizeInBytes < 1)
                throw new ArgumentException(InvalidXofSize);

            _xofSizeInBits = xofSizeInBits;
        }

        private byte[] GetResult()
        {
            var xofSizeInBytes = (int)(XofSizeInBits >> 3);

            var result = new byte[xofSizeInBytes];

            DoOutput(result, 0, xofSizeInBytes);

            return result;
        }
    }
}