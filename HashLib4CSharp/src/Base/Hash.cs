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
using HashLib4CSharp.Interfaces;

namespace HashLib4CSharp.Base
{
    internal abstract class Hash : IHash
    {
        private const string CloneNotYetImplemented = "Clone not yet implemented for '{0}'";
        private const string InvalidBufferSize = "'BufferSize' must be greater than zero";
        internal const int InternalBufferSize = 64 * 1024; // 64Kb
        private int _bufferSize;

        protected Hash(int hashSize, int blockSize)
        {
            Debug.Assert(hashSize > 0 || hashSize == -1);
            Debug.Assert(blockSize > 0 || blockSize == -1);
            HashSize = hashSize;
            BlockSize = blockSize;
            BufferSize = InternalBufferSize;
        }

        public virtual string Name => GetType().Name;
        public virtual int BlockSize { get; }
        public virtual int HashSize { get; }

        public int BufferSize
        {
            get => _bufferSize;
            set
            {
                if (value <= 0) throw new ArgumentException(InvalidBufferSize);
                _bufferSize = value;
            }
        }
        public abstract void TransformByteSpan(ReadOnlySpan<byte> data);

        public virtual IHash Clone() =>
            throw new NotImplementedException(string.Format(CloneNotYetImplemented, Name));

        public override string ToString() => Name;

        public abstract void Initialize();
        public abstract IHashResult TransformFinal();
    }
}