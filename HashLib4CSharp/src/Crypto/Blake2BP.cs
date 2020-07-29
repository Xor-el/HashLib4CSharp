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
    internal sealed class Blake2BP : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        private const int BlockSizeInBytes = 128;
        private const int OutSizeInBytes = 64;
        private const int ParallelismDegree = 4;

        private byte[] _key;
        private Blake2B[] _leafHashes;
        private byte[] _buffer;
        private ulong _bufferLength;
        private Blake2B _rootHash;

        private Blake2BP(int hashSize) : base(hashSize, BlockSizeInBytes)
        {
        }

        internal Blake2BP(int hashSize, byte[] key)
            : base(hashSize, BlockSizeInBytes)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            _key = ArrayUtils.Clone(key);
            _leafHashes = new Blake2B[ParallelismDegree];
            _buffer = new byte[ParallelismDegree * BlockSizeInBytes];
            _rootHash = Blake2BPCreateRoot();
            for (var i = 0; i < ParallelismDegree; i++)
                _leafHashes[i] = Blake2BPCreateLeaf((ulong)i);
        }

        ~Blake2BP()
        {
            Clear();
        }

        public override IHash Clone() =>
            new Blake2BP(HashSize)
            {
                _key = ArrayUtils.Clone(_key),
                _rootHash = _rootHash.CloneInternal(),
                _buffer = ArrayUtils.Clone(_buffer),
                _leafHashes = DeepCloneBlake2BInstances(_leafHashes),
                _bufferLength = _bufferLength,
                BufferSize = BufferSize
            };

        private Blake2B[] DeepCloneBlake2BInstances(Blake2B[] leafHashes)
        {
            if (leafHashes == null) return null;
            var result = new Blake2B[leafHashes.Length];
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

                DoBlake2BParallel(dataPtr2, dataLength);

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
        /// <br />Blake2B defaults to setting the expected output length <br />
        /// from <c>Config.HashSize</c>. <br />In some cases, however,
        /// we do not want this, as the output length <br />
        /// of these instances is given by <c>TreeConfig.InnerSize</c>
        /// instead. <br />
        /// </summary>
        private static Blake2B Blake2BPCreateLeafParam(Blake2BConfig config, Blake2BTreeConfig treeConfig) =>
            new Blake2B(config, treeConfig);

        private Blake2B Blake2BPCreateLeaf(ulong offset)
        {
            var config = new Blake2BConfig(OutSizeInBytes) { Key = _key };

            var treeConfig = new Blake2BTreeConfig
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

            return Blake2BPCreateLeafParam(config, treeConfig);
        }

        private Blake2B Blake2BPCreateRoot()
        {
            var config = new Blake2BConfig(HashSize) { Key = _key };

            var treeConfig = new Blake2BTreeConfig
            {
                FanOut = ParallelismDegree,
                MaxDepth = 2,
                NodeDepth = 1,
                LeafSize = 0,
                NodeOffset = 0,
                InnerHashSize = OutSizeInBytes,
                IsLastNode = true
            };

            return new Blake2B(config, treeConfig, false);
        }

        private unsafe void Blake2BParallel(int idx, void* dataPtr, ulong counter)
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

        private unsafe void DoBlake2BParallel(void* dataPtr, ulong counter)
        {
            // single threaded version
            //      for (var idx = 0; idx < ParallelismDegree; i++)
            //       Blake2BParallel(idx, dataPtr, counter);

            // multi threaded version
            Parallel.For(0, ParallelismDegree, idx => Blake2BParallel(idx, dataPtr, counter));
        }

        private void Clear()
        {
            ArrayUtils.ZeroFill(_key);
            ArrayUtils.ZeroFill(_buffer);
            ArrayUtils.ZeroFill(_leafHashes);
        }
    }
}