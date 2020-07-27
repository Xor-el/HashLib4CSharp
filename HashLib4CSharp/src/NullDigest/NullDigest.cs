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
using System.IO;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;

namespace HashLib4CSharp.NullDigest
{
    internal sealed class NullDigest : Hash, ITransformBlock
    {
        private readonly MemoryStream _out;

        private const string HashSizeNotImplemented = "HashSize Not Implemented For '{0}'";
        private const string BlockSizeNotImplemented = "BlockSize Not Implemented For '{0}'";

        public NullDigest() : base(-1, -1) // Dummy State
        {
            _out = new MemoryStream();
        }

        ~NullDigest()
        {
            _out?.Flush();
            _out?.Dispose();
        }

        public override int HashSize =>
            throw new NotImplementedException(string.Format(HashSizeNotImplemented, Name));

        public override int BlockSize =>
            throw new NotImplementedException(string.Format(BlockSizeNotImplemented, Name));

        public override IHash Clone()
        {
            var hashInstance = new NullDigest();

            var buffer = _out.ToArray();
            hashInstance._out.Write(buffer, 0, buffer.Length);

            hashInstance._out.Position = _out.Position;

            hashInstance.BufferSize = BufferSize;

            return hashInstance;
        }

        public override void Initialize()
        {
            _out.Flush();
            _out.SetLength(0);
            _out.Capacity = 0;
            _out.Position = 0;
        }

        public override IHashResult TransformFinal()
        {
            byte[] buffer;
            try
            {
                if (_out.Length > 0)
                {
                    _out.Position = 0;
                    var size = (int)_out.Length;
                    buffer = new byte[size];
                    _out.Read(buffer, 0, size);
                }
                else
                {
                    buffer = new byte[0];
                }
            }
            finally
            {
                Initialize();
            }

            return new HashResult(buffer);
        }

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length > 0)
            {
                _out.Write(data);
            }
        }
    }
}