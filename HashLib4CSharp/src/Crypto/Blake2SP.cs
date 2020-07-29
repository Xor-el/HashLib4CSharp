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
using System.Threading.Tasks;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Params;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class Blake2SP : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        private const int BlockSizeInBytes = 64;
        private const int OutSizeInBytes = 32;
        private const int ParallelismDegree = 8;

        private byte[] _key;
        private Blake2S[] _leafHashes;
        private byte[] _buffer;
        private ulong _bufferLength;
        private Blake2S _rootHash;

        private Blake2SP(int hashSize) : base(hashSize, BlockSizeInBytes)
        {
        }

        internal Blake2SP(int hashSize, byte[] key)
            : base(hashSize, BlockSizeInBytes)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            _key = ArrayUtils.Clone(key);
            _leafHashes = new Blake2S[ParallelismDegree];
            _buffer = new byte[ParallelismDegree * BlockSizeInBytes];
            _rootHash = Blake2SPCreateRoot();
            for (var idx = 0; idx < ParallelismDegree; idx++)
                _leafHashes[idx] = Blake2SPCreateLeaf((ulong)idx);
        }

        ~Blake2SP()
        {
            Clear();
        }

        public override IHash Clone() =>
            new Blake2SP(HashSize)
            {
                _key = ArrayUtils.Clone(_key),
                _rootHash = _rootHash.CloneInternal(),
                _buffer = ArrayUtils.Clone(_buffer),
                _leafHashes = DeepCloneBlake2SInstances(_leafHashes),
                _bufferLength = _bufferLength,
                BufferSize = BufferSize
            };

        private Blake2S[] DeepCloneBlake2SInstances(Blake2S[] leafHashes)
        {
            if (leafHashes == null) return null;
            var result = new Blake2S[leafHashes.Length];
            for (var idx = 0; idx < _leafHashes.Length; idx++)
            {
                result[idx] = _leafHashes[idx].CloneInternal();
            }

            return result;
        }

        public override void Initialize()
        {
            _rootHash.Initialize();
            for (var idx = 0; idx < ParallelismDegree; idx++)
            {
                _leafHashes[idx].Initialize();
            }

            ArrayUtils.ZeroFill(_buffer);
            _bufferLength = 0;
        }

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var dataLength = (ulong)data.Length;

            fixed (byte* dataPtr = data, bufferPtr = _buffer)
            {
                var dataPtr2 = dataPtr;

                var left = _bufferLength;
                var fill = (ulong)_buffer.Length - left;

                if (left > 0 && dataLength >= fill)
                {
                    PointerUtils.MemMove(dataPtr2, bufferPtr + left, (int)fill);

                    for (var idx = 0; idx < ParallelismDegree; idx++)
                    {
                        _leafHashes[idx].TransformByteSpan(_buffer.AsSpan().Slice(idx * BlockSizeInBytes, BlockSizeInBytes));
                    }

                    dataPtr2 += fill;
                    dataLength -= fill;
                    left = 0;
                }

                DoBlake2SParallel(dataPtr2, dataLength);

                dataPtr2 += dataLength - dataLength % (ParallelismDegree * BlockSizeInBytes);
                dataLength %= ParallelismDegree * BlockSizeInBytes;

                if (dataLength > 0)
                    PointerUtils.MemMove(bufferPtr + left, dataPtr2, (int)dataLength);

                _bufferLength = left + dataLength;
            }
        }

        public override IHashResult TransformFinal()
        {
            int idx;

            var hash = new byte[ParallelismDegree][];

            for (idx = 0; idx < hash.Length; idx++)
            {
                hash[idx] = new byte[OutSizeInBytes];
            }

            for (idx = 0; idx < ParallelismDegree; idx++)
            {
                if (_bufferLength > (ulong)(idx * BlockSizeInBytes))
                {
                    var left = _bufferLength - (ulong)(idx * BlockSizeInBytes);
                    left = Math.Min(left, BlockSizeInBytes);
                    _leafHashes[idx].TransformByteSpan(_buffer.AsSpan().Slice(idx * BlockSizeInBytes, (int)left));
                }

                hash[idx] = _leafHashes[idx].TransformFinal().GetBytes();
            }

            for (idx = 0; idx < ParallelismDegree; idx++)
                _rootHash.TransformByteSpan(hash[idx].AsSpan().Slice(0, OutSizeInBytes));

            var result = _rootHash.TransformFinal();

            Initialize();

            return result;
        }

        public override string Name => $"{GetType().Name}_{HashSize * 8}";

        /// <summary>
        /// <br />Blake2S defaults to setting the expected output length <br />
        /// from <c>Config.HashSize</c>. <br />In some cases, however,
        /// we do not want this, as the output length <br />
        /// of these instances is given by <c>TreeConfig.InnerSize</c>
        /// instead. <br />
        /// </summary>
        private static Blake2S Blake2SPCreateLeafParam(Blake2SConfig config, Blake2STreeConfig treeConfig) =>
            new Blake2S(config, treeConfig);

        private Blake2S Blake2SPCreateLeaf(ulong offset)
        {
            var config = new Blake2SConfig(OutSizeInBytes) { Key = _key };

            var treeConfig = new Blake2STreeConfig
            {
                FanOut = ParallelismDegree,
                MaxDepth = 2,
                NodeDepth = 0,
                LeafSize = 0,
                NodeOffset = offset,
                InnerHashSize = OutSizeInBytes
            };

            if (offset == ParallelismDegree - 1)
                treeConfig.IsLastNode = true;

            return Blake2SPCreateLeafParam(config, treeConfig);
        }

        private Blake2S Blake2SPCreateRoot()
        {
            var config = new Blake2SConfig(HashSize) { Key = _key };

            var treeConfig = new Blake2STreeConfig
            {
                FanOut = ParallelismDegree,
                MaxDepth = 2,
                NodeDepth = 1,
                LeafSize = 0,
                NodeOffset = 0,
                InnerHashSize = OutSizeInBytes,
                IsLastNode = true
            };

            return new Blake2S(config, treeConfig, false);
        }

        private unsafe void Blake2SParallel(int idx, void* dataPtr, ulong counter)
        {
            Span<byte> buffer = stackalloc byte[BlockSizeInBytes];
            var dataPtr2 = (byte*)dataPtr;
            dataPtr2 += idx * BlockSizeInBytes;

            fixed (byte* bufferPtr = buffer)
            {
                while (counter >= ParallelismDegree * BlockSizeInBytes)
                {
                    PointerUtils.MemMove(bufferPtr, dataPtr2, BlockSizeInBytes);
                    _leafHashes[idx].TransformByteSpan(buffer.Slice(0, BlockSizeInBytes));
                    dataPtr2 += (ulong)(ParallelismDegree * BlockSizeInBytes);
                    counter -= ParallelismDegree * BlockSizeInBytes;
                }
            }
        }

        private unsafe void DoBlake2SParallel(void* dataPtr, ulong counter)
        {
            // single threaded version
            //      for (var idx = 0; idx < ParallelismDegree; i++)
            //       Blake2SParallel(idx, dataPtr, counter);

            // multi threaded version
            Parallel.For(0, ParallelismDegree, idx => Blake2SParallel(idx, dataPtr, counter));
        }

        private void Clear()
        {
            ArrayUtils.ZeroFill(_key);
            ArrayUtils.ZeroFill(_buffer);
            ArrayUtils.ZeroFill(_leafHashes);
        }
    }
}