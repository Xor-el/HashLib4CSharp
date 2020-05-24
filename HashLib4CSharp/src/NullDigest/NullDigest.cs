using System.IO;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

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
            throw new NotImplementedHashLibException(string.Format(HashSizeNotImplemented, Name));

        public override int BlockSize =>
            throw new NotImplementedHashLibException(string.Format(BlockSizeNotImplemented, Name));

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
                    var size = (int) _out.Length;
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

        public override void TransformBytes(byte[] data, int index, int length)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            if (data.Length > 0)
            {
                _out.Write(data, index, length);
            }
        }
    }
}