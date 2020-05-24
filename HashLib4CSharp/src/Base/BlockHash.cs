using System.Diagnostics;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Base
{
    internal abstract class BlockHash : Hash, IBlockHash
    {
        private ulong _processedBytesCount;

        protected internal BlockHash(int hashSize, int blockSize, int bufferSize = -1) : base(hashSize, blockSize)
        {
            if (bufferSize == -1)
                bufferSize = blockSize;

            Buffer = new HashBuffer(bufferSize);
        }

        protected HashBuffer Buffer { get; set; }

        protected ulong ProcessedBytesCount
        {
            get => _processedBytesCount;
            set => _processedBytesCount = value;
        }

        public override void Initialize()
        {
            Buffer.Initialize();
            ProcessedBytesCount = 0;
        }

        public override unsafe void TransformBytes(byte[] data, int index, int length)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            Debug.Assert(index >= 0);
            Debug.Assert(length >= 0);
            Debug.Assert(index + length <= data.Length);

            fixed (byte* src = data)
            {
                if (!Buffer.IsEmpty)
                    if (Buffer.Feed(src, data.Length, ref index, ref length, ref _processedBytesCount))
                        TransformBuffer();

                while (length >= Buffer.Length)
                {
                    ProcessedBytesCount += (ulong) Buffer.Length;
                    TransformBlock(src, Buffer.Length, index);
                    index += Buffer.Length;
                    length -= Buffer.Length;
                }

                if (length > 0)
                    Buffer.Feed(src, data.Length, ref index, ref length, ref _processedBytesCount);
            }
        }

        public override IHashResult TransformFinal()
        {
            Finish();
            Debug.Assert(Buffer.IsEmpty);
            var temp = GetResult();
            Debug.Assert(temp.Length == HashSize);
            Initialize();
            return new HashResult(temp);
        }

        private unsafe void TransformBuffer()
        {
            Debug.Assert(Buffer.IsFull);
            var temp = Buffer.GetBytes();
            fixed (byte* tempPtr = temp)
            {
                TransformBlock(tempPtr, Buffer.Length, 0);
            }
        }

        protected abstract void Finish();

        protected abstract unsafe void TransformBlock(void* data,
            int dataLength, int index);

        protected abstract byte[] GetResult();
    }
}