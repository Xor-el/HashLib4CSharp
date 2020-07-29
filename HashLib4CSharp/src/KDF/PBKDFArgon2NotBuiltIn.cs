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
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Enum;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Params;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.KDF
{
    public sealed class Argon2Parameters
    {
        private readonly byte[] _salt;
        private readonly byte[] _secret;
        private readonly byte[] _additional;

        public byte[] Salt => ArrayUtils.Clone(_salt);
        public byte[] Secret => ArrayUtils.Clone(_secret);
        public byte[] Additional => ArrayUtils.Clone(_additional);

        public int Iterations { get; }

        public int Memory { get; }

        public int Lanes { get; }

        public Argon2Type Type { get; }

        public Argon2Version Version { get; }

        public Argon2Parameters(Argon2Type type, byte[] salt, byte[] secret, byte[] additional,
            int iterations, int memory, int lanes, Argon2Version version)
        {
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (secret == null) throw new ArgumentNullException(nameof(secret));
            if (additional == null) throw new ArgumentNullException(nameof(additional));

            _salt = ArrayUtils.Clone(salt);
            _secret = ArrayUtils.Clone(secret);
            _additional = ArrayUtils.Clone(additional);

            Iterations = iterations;
            Memory = memory;
            Lanes = lanes;
            Type = type;
            Version = version;
        }

        ~Argon2Parameters()
        {
            Clear();
        }

        public void Clear()
        {
            ArrayUtils.ZeroFill(_salt);
            ArrayUtils.ZeroFill(_secret);
            ArrayUtils.ZeroFill(_additional);
        }

        public Argon2Parameters Clone() =>
            new Argon2Parameters(Type, _salt, _secret, _additional, Iterations, Memory, Lanes, Version);
    }

    public sealed class Argon2ParametersBuilder
    {
        private const int DEFAULT_ITERATIONS = 3;
        private const int DEFAULT_MEMORY_COST = 12;
        private const int DEFAULT_LANES = 1;
        private const Argon2Type DEFAULT_TYPE = Argon2Type.DataIndependentAddressing;
        private const Argon2Version DEFAULT_VERSION = Argon2Version.Nineteen;

        private byte[] _salt;
        private byte[] _secret;
        private byte[] _additional;
        private Argon2Type _type;
        private Argon2Version _version;
        private int _iterations;
        private int _memory;
        private int _lanes;

        private Argon2ParametersBuilder()
        {
            _salt = new byte[0];
            _secret = new byte[0];
            _additional = new byte[0];
            _type = DEFAULT_TYPE;
            _version = DEFAULT_VERSION;
            _iterations = DEFAULT_ITERATIONS;
            _memory = 1 << DEFAULT_MEMORY_COST;
            _lanes = DEFAULT_LANES;
        }

        ~Argon2ParametersBuilder()
        {
            Clear();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2Parameters Build() =>
            new Argon2Parameters(_type, _salt, _secret, _additional,
                _iterations, _memory, _lanes, _version);

        public void Clear()
        {
            ArrayUtils.ZeroFill(_salt);
            ArrayUtils.ZeroFill(_secret);
            ArrayUtils.ZeroFill(_additional);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithSalt(byte[] salt)
        {
            _salt = salt != null
                ? ArrayUtils.Clone(salt)
                : throw new ArgumentNullException(nameof(salt));
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithAdditional(byte[] additional)
        {
            _additional = additional != null
                ? ArrayUtils.Clone(additional)
                : throw new ArgumentNullException(nameof(additional));
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithSecret(byte[] secret)
        {
            _secret = secret != null
                ? ArrayUtils.Clone(secret)
                : throw new ArgumentNullException(nameof(secret));
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithIterations(int iterations)
        {
            _iterations = iterations;
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithMemoryAsKiB(int memory)
        {
            _memory = memory;
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithMemoryPowOfTwo(int memory)
        {
            _memory = 1 << memory;
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithParallelism(int parallelism)
        {
            _lanes = parallelism;
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithType(Argon2Type type)
        {
            _type = type;
            return this;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Argon2ParametersBuilder WithVersion(Argon2Version version)
        {
            _version = version;
            return this;
        }

        public static Argon2ParametersBuilder DefaultBuilder() => new Argon2ParametersBuilder();
    }

    /// <summary>
    /// Argon2 PBKDF - Based on the results of https://octets-hashing.net/
    /// and https://www.ietf.org/archive/id/draft-irtf-cfrg-argon2-03.txt
    /// </summary>
    internal sealed class PBKDFArgon2NotBuiltIn : KDFNotBuiltIn, IPBKDFArgon2NotBuiltIn
    {
        private const string LanesTooSmall = "Lanes must be greater than '{0}'";
        private const string LanesTooBig = "Lanes must be less than '{0}'";
        private const string MemoryTooSmall = "Memory is too small: '{0}', expected at least '{1}'";
        private const string IterationsTooSmall = "Iterations is less than: '{0}'";
        private const string InvalidOutputByteCount = "{0} less than '{1}'";

        private const int ARGON2_BLOCK_SIZE = 1024;
        private const int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

        private const int ARGON2_ADDRESSES_IN_BLOCK = 128;

        private const int ARGON2_PREHASH_DIGEST_LENGTH = 64;
        private const int ARGON2_PREHASH_SEED_LENGTH = 72;

        private const int ARGON2_SYNC_POINTS = 4;

        // Minimum and maximum number of lanes (degree of parallelism)
        private const int MIN_PARALLELISM = 1;

        private const int MAX_PARALLELISM = 16777216;

        // Minimum digest size in bytes
        private const int MIN_OUTLEN = 4;

        // Minimum and maximum number of passes
        private const int MIN_ITERATIONS = 1;

        private byte[] _digest, _password;
        private Block[] _memory;
        private Argon2Parameters _parameters;
        private int _segmentLength, _laneLength;


        private PBKDFArgon2NotBuiltIn()
        {
        }

        /// <summary>
        /// Initialise the <see cref="PBKDFArgon2NotBuiltIn" />
        /// from the octets and parameter object.
        /// </summary>
        /// <param name="password">
        /// the octets to use.
        /// </param>
        /// <param name="parameters">
        /// Argon2 configuration.
        /// </param>
        internal PBKDFArgon2NotBuiltIn(byte[] password, Argon2Parameters parameters)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            _password = ArrayUtils.Clone(password);
            _parameters = parameters.Clone();

            if (_parameters.Lanes < MIN_PARALLELISM)
                throw new ArgumentException(string.Format(LanesTooSmall, MIN_PARALLELISM));

            if (_parameters.Lanes > MAX_PARALLELISM)
                throw new ArgumentException(string.Format(LanesTooBig, MAX_PARALLELISM));

            if (_parameters.Memory < 8 * _parameters.Lanes)
                throw new ArgumentException(string.Format(MemoryTooSmall, _parameters.Memory,
                    8 * _parameters.Lanes));

            if (_parameters.Iterations < MIN_ITERATIONS)
                throw new ArgumentException(string.Format(IterationsTooSmall, MIN_ITERATIONS));

            DoInit(parameters);
        }

        public override void Clear() => ArrayUtils.ZeroFill(_password);

        public override unsafe byte[] GetBytes(int byteCount)
        {
            if (byteCount <= MIN_OUTLEN)
                throw new ArgumentException(
                    string.Format(InvalidOutputByteCount, nameof(byteCount), MIN_OUTLEN));

            Initialize(_password, byteCount);
            DoFillMemoryBlocks();

            Digest(byteCount);

            var result = new byte[byteCount];

            fixed (byte* digestPtr = _digest, resultPtr = result)
            {
                PointerUtils.MemMove(resultPtr, digestPtr, byteCount);
            }

            Reset();

            return result;
        }

        public override async Task<byte[]> GetBytesAsync(int byteCount,
            CancellationToken cancellationToken = default) =>
            await Task.Run(() => GetBytes(byteCount), cancellationToken);

        public override string Name => GetType().Name;

        public override string ToString() => Name;

        public override IKDFNotBuiltIn Clone() =>
            new PBKDFArgon2NotBuiltIn()
            {
                _digest = ArrayUtils.Clone(_digest),
                _password = ArrayUtils.Clone(_password),
                _memory = DeepCopyBlockArray(_memory),
                _parameters = _parameters.Clone(),
                _segmentLength = _segmentLength,
                _laneLength = _laneLength
            };

        private static Block[] DeepCopyBlockArray(Block[] blocks)
        {
            if (blocks == null) throw new ArgumentNullException(nameof(blocks));
            var result = new Block[blocks.Length];

            for (var idx = 0; idx < result.Length; idx++)
            {
                result[idx] = blocks[idx].Clone();
            }

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void DoInit(Argon2Parameters parameters)
        {
            // 2. Align memory size
            // Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
            var memoryBlocks = parameters.Memory;

            memoryBlocks = Math.Max(memoryBlocks, 2 * ARGON2_SYNC_POINTS * parameters.Lanes);

            _segmentLength = memoryBlocks / (_parameters.Lanes * ARGON2_SYNC_POINTS);
            _laneLength = _segmentLength * ARGON2_SYNC_POINTS;

            // Ensure that all segments have equal length
            memoryBlocks = _segmentLength * parameters.Lanes * ARGON2_SYNC_POINTS;

            InitializeMemory(memoryBlocks);
        }

        private void InitializeMemory(int memoryBlocks)
        {
            _memory = new Block[memoryBlocks];
            for (var idx = 0; idx < _memory.Length; idx++)
                _memory[idx] = Block.DefaultBlock();
        }

        private void Reset()
        {
            // Reset memory.
            foreach (var b in _memory)
            {
                b.Clear();
            }

            ArrayUtils.ZeroFill(_digest);
        }

        private static byte[] InitialHash(Argon2Parameters parameters, int outputLength,
            byte[] password)
        {
            var blake2B = MakeBlake2BInstanceAndInitialize(ARGON2_PREHASH_DIGEST_LENGTH);

            AddIntToLittleEndian(blake2B, parameters.Lanes);
            AddIntToLittleEndian(blake2B, outputLength);
            AddIntToLittleEndian(blake2B, parameters.Memory);
            AddIntToLittleEndian(blake2B, parameters.Iterations);
            AddIntToLittleEndian(blake2B, (int)parameters.Version);
            AddIntToLittleEndian(blake2B, (int)parameters.Type);

            AddByteString(blake2B, password);
            AddByteString(blake2B, parameters.Salt);

            AddByteString(blake2B, parameters.Secret);
            AddByteString(blake2B, parameters.Additional);

            return blake2B.TransformFinal().GetBytes();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AddByteString(Blake2B hashInstance, byte[] octets)
        {
            if (octets.Length > 0)
            {
                AddIntToLittleEndian(hashInstance, octets.Length);
                hashInstance.TransformByteSpan(octets);
            }
            else
            {
                AddIntToLittleEndian(hashInstance, 0);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AddIntToLittleEndian(Blake2B hashInstance, int lanes) =>
            hashInstance.TransformByteSpan(Converters.ReadUInt32AsBytesLE((uint)lanes));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Blake2B MakeBlake2BInstanceAndInitialize(int hashSize)
        {
            var hashInstance = new Blake2B(new Blake2BConfig(hashSize));
            hashInstance.Initialize();
            return hashInstance;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe byte[] GetInitialHashLong(byte[] initialHash, byte[] appendix)
        {
            var result = new byte[ARGON2_PREHASH_SEED_LENGTH];

            fixed (byte* initialHashPtr = initialHash, resultPtr = result, appendixPtr = appendix)
            {
                PointerUtils.MemMove(resultPtr, initialHashPtr, ARGON2_PREHASH_DIGEST_LENGTH);
                PointerUtils.MemMove(resultPtr + ARGON2_PREHASH_DIGEST_LENGTH, appendixPtr, 4);
            }

            return result;
        }

        private static unsafe byte[] Hash(byte[] input, int outputLength)
        {
            Blake2B blake2B;

            const int blake2BLength = 64;

            var result = new byte[outputLength];
            var outputLengthBytes = Converters.ReadUInt32AsBytesLE((uint)outputLength);

            if (outputLength <= blake2BLength)
            {
                blake2B = MakeBlake2BInstanceAndInitialize(outputLength);

                blake2B.TransformByteSpan(outputLengthBytes);
                blake2B.TransformByteSpan(input);
                result = blake2B.TransformFinal().GetBytes();
            }
            else
            {
                blake2B = MakeBlake2BInstanceAndInitialize(blake2BLength);

                blake2B.TransformByteSpan(outputLengthBytes);
                blake2B.TransformByteSpan(input);
                var buffer = blake2B.TransformFinal().GetBytes();

                fixed (byte* bufferPtr = buffer, resultPtr = result)
                {
                    PointerUtils.MemMove(resultPtr, bufferPtr, blake2BLength / 2);
                }

                var count = (outputLength + 31) / 32 - 2;

                var position = blake2BLength / 2;

                var idx = 2;

                while (idx <= count)
                {
                    blake2B.TransformByteSpan(buffer);
                    buffer = blake2B.TransformFinal().GetBytes();

                    fixed (byte* bufferPtr = buffer, resultPtr = result)
                    {
                        PointerUtils.MemMove(resultPtr + position, bufferPtr, blake2BLength / 2);
                    }

                    idx++;
                    position += blake2BLength / 2;
                }

                var lastLength = outputLength - 32 * count;

                blake2B = MakeBlake2BInstanceAndInitialize(lastLength);

                blake2B.TransformByteSpan(buffer);
                buffer = blake2B.TransformFinal().GetBytes();

                fixed (byte* bufferPtr = buffer, resultPtr = result)
                {
                    PointerUtils.MemMove(resultPtr + position, bufferPtr, lastLength);
                }
            }

            Debug.Assert(result.Length == outputLength);
            return result;
        }

        private void Digest(int outputLength)
        {
            var finalBlock = _memory[_laneLength - 1];

            // XOR the last blocks
            for (var idx = 1; idx < _parameters.Lanes; idx++)
            {
                var lastBlockInLane = idx * _laneLength + (_laneLength - 1);
                finalBlock.XorWith(_memory[lastBlockInLane]);
            }

            var finalBlockBytes = finalBlock.ToBytes();

            _digest = Hash(finalBlockBytes, outputLength);
        }

        private void FillFirstBlocks(byte[] initialHash)
        {
            var zeroBytes = new byte[] { 0, 0, 0, 0 };
            var oneBytes = new byte[] { 1, 0, 0, 0 };

            var initialHashWithZeros = GetInitialHashLong(initialHash, zeroBytes);
            var initialHashWithOnes = GetInitialHashLong(initialHash, oneBytes);

            for (var idx = 0; idx < _parameters.Lanes; idx++)
            {
                Converters.ReadUInt32AsBytesLE((uint)idx, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4);
                Converters.ReadUInt32AsBytesLE((uint)idx, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4);

                var blockHashBytes = Hash(initialHashWithZeros, ARGON2_BLOCK_SIZE);
                _memory[idx * _laneLength].FromBytes(blockHashBytes);

                blockHashBytes = Hash(initialHashWithOnes, ARGON2_BLOCK_SIZE);
                _memory[idx * _laneLength + 1].FromBytes(blockHashBytes);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool IsDataIndependentAddressing(Position position) =>
            _parameters.Type == Argon2Type.DataIndependentAddressing ||
            _parameters.Type == Argon2Type.HybridAddressing && position.Pass == 0
                                                            && position.Slice < ARGON2_SYNC_POINTS / 2;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Initialize(byte[] password, int outputLength)
        {
            var initialHash = InitialHash(_parameters, outputLength, password);
            FillFirstBlocks(initialHash);
        }

        private void FillSegment(BlockFiller blockFiller, Position position)
        {
            var dataIndependentAddressing = IsDataIndependentAddressing(position);
            var startingIndex = GetStartingIndex(position);
            var currentOffset = position.Lane * _laneLength +
                                position.Slice * _segmentLength + startingIndex;
            var prevOffset = GetPrevOffset(currentOffset);

            var addressBlock = Block.DefaultBlock();
            var inputBlock = Block.DefaultBlock();
            var zeroBlock = Block.DefaultBlock();

            if (dataIndependentAddressing)
            {
                blockFiller.AddressBlock.Clear();
                blockFiller.ZeroBlock.Clear();
                blockFiller.InputBlock.Clear();

                InitAddressBlocks(blockFiller, position, zeroBlock, inputBlock, addressBlock);
            }

            position.Index = startingIndex;

            while (position.Index < _segmentLength)
            {
                prevOffset = RotatePrevOffset(currentOffset, prevOffset);

                var pseudoRandom = GetPseudoRandom(blockFiller, position, addressBlock,
                    inputBlock, zeroBlock, prevOffset, dataIndependentAddressing);
                var refLane = GetRefLane(position, pseudoRandom);
                var refColumn = GetRefColumn(position, pseudoRandom, refLane == position.Lane);

                // 2 Creating a new block
                var prevBlock = _memory[prevOffset];
                var refBlock = _memory[_laneLength * refLane + refColumn];
                var currentBlock = _memory[currentOffset];

                if (IsWithXor(position))
                {
                    blockFiller.FillBlockWithXor(prevBlock, refBlock, currentBlock);
                }
                else
                {
                    blockFiller.FillBlock(prevBlock, refBlock, currentBlock);
                }

                position.Index++;
                currentOffset++;
                prevOffset++;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void FillMemoryBlocks(BlockFiller blockFiller, Position position) => FillSegment(blockFiller, position);

        private void DoFillMemoryBlocks()
        {
            /*  // single threaded version
              var filler = BlockFiller.DefaultBlockFiller();
              var position = Position.DefaultPosition();
  
              var iterations = _parameters.Iterations;
              var lanes = _parameters.Lanes;
  
              for (var idx = 0; idx < iterations; idx++)
              {
                  for (var jdx = 0; jdx < ARGON2_SYNC_POINTS; jdx++)
                  {
                      for (var kdx = 0; kdx < lanes; kdx++)
                      {
                          position.Update(idx, kdx, jdx, 0);
                          FillMemoryBlocks(filler, position);
                      }
                  }
              }
  */
            // multi threaded version
            var iterations = _parameters.Iterations;
            var lanes = _parameters.Lanes;

            for (var idx = 0; idx < iterations; idx++)
            {
                for (var jdx = 0; jdx < ARGON2_SYNC_POINTS; jdx++)
                {
                    Parallel.For(0, lanes, kdx =>
                    {
                        var filler = BlockFiller.DefaultBlockFiller();
                        var position = Position.CreatePosition(idx, kdx, jdx, 0);
                        FillMemoryBlocks(filler, position);
                    });
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool IsWithXor(Position position) =>
            !(position.Pass == 0 || _parameters.Version == Argon2Version.Sixteen);

        private int GetRefColumn(Position position, ulong pseudoRandom, bool sameLane)
        {
            int referenceAreaSize, startPosition, temp;

            if (position.Pass == 0)
            {
                startPosition = 0;

                if (sameLane)
                {
                    // The same lane => add current segment
                    referenceAreaSize = position.Slice * _segmentLength +
                        position.Index - 1;
                }
                else
                {
                    temp = position.Index == 0 ? -1 : 0;

                    referenceAreaSize = position.Slice * _segmentLength + temp;
                }
            }
            else
            {
                startPosition = (position.Slice + 1) * _segmentLength % _laneLength;

                if (sameLane)
                {
                    referenceAreaSize = _laneLength - _segmentLength + position.Index - 1;
                }
                else
                {
                    temp = position.Index == 0 ? -1 : 0;

                    referenceAreaSize = _laneLength - _segmentLength + temp;
                }
            }

            var relativePosition = pseudoRandom & 0xFFFFFFFF;
            relativePosition = (relativePosition * relativePosition) >> 32;
            relativePosition = (ulong)referenceAreaSize - 1 -
                               (((ulong)referenceAreaSize * relativePosition) >> 32);

            return (int)(((ulong)startPosition + relativePosition) % (ulong)_laneLength);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private int GetRefLane(Position position, ulong pseudoRandom)
        {
            var refLane = (int)((pseudoRandom >> 32) % (ulong)_parameters.Lanes);

            if (position.Pass == 0 && position.Slice == 0)
                // Can not reference other lanes yet
                refLane = position.Lane;

            return refLane;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ulong GetPseudoRandom(BlockFiller blockFiller, Position position,
            Block addressBlock, Block inputBlock, Block zeroBlock, int prevOffset,
            bool dataIndependentAddressing)
        {
            if (!dataIndependentAddressing) return _memory[prevOffset].V[0];
            if (position.Index % ARGON2_ADDRESSES_IN_BLOCK == 0)
                NextAddresses(blockFiller, zeroBlock, inputBlock, addressBlock);

            return addressBlock.V[position.Index % ARGON2_ADDRESSES_IN_BLOCK];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private int RotatePrevOffset(int currentOffset, int prevOffset) =>
            currentOffset % _laneLength == 1 ? currentOffset - 1 : prevOffset;

        private void InitAddressBlocks(BlockFiller blockFiller, Position position,
            Block zeroBlock, Block inputBlock, Block addressBlock)
        {
            inputBlock.V[0] = IntToUInt64(position.Pass);
            inputBlock.V[1] = IntToUInt64(position.Lane);
            inputBlock.V[2] = IntToUInt64(position.Slice);
            inputBlock.V[3] = IntToUInt64(_memory.Length);
            inputBlock.V[4] = IntToUInt64(_parameters.Iterations);
            inputBlock.V[5] = IntToUInt64((int)_parameters.Type);

            // Don't forget to generate the first block of addresses: */
            if (position.Pass == 0 && position.Slice == 0)
                NextAddresses(blockFiller, zeroBlock, inputBlock, addressBlock);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void NextAddresses(BlockFiller blockFiller, Block zeroBlock, Block inputBlock,
            Block addressBlock)
        {
            inputBlock.V[6]++;
            blockFiller.FillBlock(zeroBlock, inputBlock, addressBlock);
            blockFiller.FillBlock(zeroBlock, addressBlock, addressBlock);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong IntToUInt64(int x) => (ulong)(x & 0xFFFFFFFF);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private int GetPrevOffset(int currentOffset) =>
            currentOffset % _laneLength == 0 ? currentOffset + _laneLength - 1 : currentOffset - 1;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetStartingIndex(Position position) => position.Pass == 0 && position.Slice == 0 ? 2 : 0;

        private sealed class BlockFiller
        {
            private Block R { get; }
            private Block Z { get; }
            public Block AddressBlock { get; }
            public Block ZeroBlock { get; }
            public Block InputBlock { get; }

            private BlockFiller()
            {
                R = Block.DefaultBlock();
                Z = Block.DefaultBlock();
                AddressBlock = Block.DefaultBlock();
                ZeroBlock = Block.DefaultBlock();
                InputBlock = Block.DefaultBlock();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void FillBlock(Block x, Block y, Block currentBlock)
            {
                if (x == ZeroBlock)
                {
                    R.CopyBlock(y);
                }
                else
                {
                    R.Xor(x, y);
                }

                Z.CopyBlock(R);
                ApplyBlake();
                currentBlock.Xor(R, Z);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void FillBlockWithXor(Block x, Block y, Block currentBlock)
            {
                R.Xor(x, y);
                Z.CopyBlock(R);
                ApplyBlake();
                currentBlock.Xor(R, Z, currentBlock);
            }

            private void ApplyBlake()
            {
                int i;

                /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , 
                 * then (16,17,..31)... finally (112,113,...127) */

                for (i = 0; i < 8; i++)
                {
                    var i16 = 16 * i;
                    RoundFunction(Z, i16, i16 + 1, i16 + 2, i16 + 3, i16 + 4, i16 + 5,
                        i16 + 6, i16 + 7, i16 + 8, i16 + 9, i16 + 10, i16 + 11, i16 + 12,
                        i16 + 13, i16 + 14, i16 + 15);
                }

                /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), 
                then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */

                for (i = 0; i < 8; i++)
                {
                    var i2 = 2 * i;
                    RoundFunction(Z, i2, i2 + 1, i2 + 16, i2 + 17, i2 + 32, i2 + 33,
                        i2 + 48, i2 + 49, i2 + 64, i2 + 65, i2 + 80, i2 + 81, i2 + 96,
                        i2 + 97, i2 + 112, i2 + 113);
                }
            }

            private static void RoundFunction(Block block, int v0, int v1, int v2, int v3,
                int v4, int v5, int v6, int v7, int v8, int v9, int v10,
                int v11, int v12, int v13, int v14, int v15)
            {
                F(block, v0, v4, v8, v12);
                F(block, v1, v5, v9, v13);
                F(block, v2, v6, v10, v14);
                F(block, v3, v7, v11, v15);

                F(block, v0, v5, v10, v15);
                F(block, v1, v6, v11, v12);
                F(block, v2, v7, v8, v13);
                F(block, v3, v4, v9, v14);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void F(Block block, int a, int b, int c, int d)
            {
                BlaMka(block, a, b);
                RotateRight64(block, d, a, 32);

                BlaMka(block, c, d);
                RotateRight64(block, b, c, 24);

                BlaMka(block, a, b);
                RotateRight64(block, d, a, 16);

                BlaMka(block, c, d);
                RotateRight64(block, b, c, 63);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void RotateRight64(Block block, int a, int b, int c) =>
                block.V[a] = Bits.RotateRight64(block.V[a] ^ block.V[b], c);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void BlaMka(Block block, int x, int y)
            {
                const uint m = 0xFFFFFFFF;
                var xy = (block.V[x] & m) * (block.V[y] & m);

                block.V[x] = block.V[x] + block.V[y] + 2 * xy;
            }

            public static BlockFiller DefaultBlockFiller() => new BlockFiller();
        }

        private struct Position
        {
            public int Pass { get; private set; }
            public int Lane { get; private set; }
            public int Slice { get; private set; }
            public int Index { get; set; }

            public void Update(int pass, int lane, int slice, int index)
            {
                Pass = pass;
                Lane = lane;
                Slice = slice;
                Index = index;
            }

            public static Position DefaultPosition() => new Position();

            public static Position CreatePosition(int pass, int lane, int slice, int index) => new Position()
            { Pass = pass, Lane = lane, Slice = slice, Index = index };
        }

        private sealed class Block
        {
            private const string InvalidInputLength = "Input length '{0}' is not equal to blockSize '{1}'";

            private const int SIZE = ARGON2_QWORDS_IN_BLOCK;

            // 128 * 8 Byte QWords

            public ulong[] V { get; private set; }

            private Block()
            {
                V = new ulong[SIZE];
            }

            public void CopyBlock(Block other) => V = ArrayUtils.Clone(other.V);

            public void Xor(Block b1, Block b2)
            {
                for (var idx = 0; idx < SIZE; idx++)
                    V[idx] = b1.V[idx] ^ b2.V[idx];
            }

            public void Xor(Block b1, Block b2, Block b3)
            {
                for (var idx = 0; idx < SIZE; idx++)
                    V[idx] = b1.V[idx] ^ b2.V[idx] ^ b3.V[idx];
            }

            public void XorWith(Block other)
            {
                for (var idx = 0; idx < V.Length; idx++)
                    V[idx] = V[idx] ^ other.V[idx];
            }

            public void Clear()
            {
                ArrayUtils.ZeroFill(V);
            }

            public Block Clone() =>
                new Block
                {
                    V = ArrayUtils.Clone(V)
                };

            public unsafe void FromBytes(byte[] input)
            {
                if (input.Length != ARGON2_BLOCK_SIZE)
                    throw new ArgumentException(
                        string.Format(InvalidInputLength, input.Length, ARGON2_BLOCK_SIZE));

                fixed (byte* ptrInput = input)
                {
                    for (var idx = 0; idx < SIZE; idx++)
                        V[idx] = Converters.ReadBytesAsUInt64LE(ptrInput, idx * 8);
                }
            }

            public byte[] ToBytes()
            {
                var result = new byte[ARGON2_BLOCK_SIZE];
                for (var idx = 0; idx < SIZE; idx++)
                    Converters.ReadUInt64AsBytesLE(V[idx], result, idx * 8);

                return result;
            }

            public override string ToString()
            {
                var result = "";
                for (var idx = 0; idx < SIZE; idx++)
                    result += Converters.ConvertBytesToHexString(
                        Converters.ReadUInt64AsBytesLE(V[idx]));

                return result;
            }

            public static Block DefaultBlock() => new Block();
        }
    }
}