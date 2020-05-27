/*
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
{ *                             HashLib4CSharp Library                              * }
{ *                      Copyright (c) 2020 Ugochukwu Mmaduekwe                     * }
{ *                 GitHub Profile URL <https://github.com/Xor-el>                  * }

{ *  Distributed under the MIT software license, see the accompanying LICENSE file  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *   This library was sponsored by Sphere 10 Software (https://www.sphere10.com)   * }
{ *         for the purposes of supporting the XXX (https://YYY) project.           * }
{ *                                                                                 * }
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
*/

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Base
{
    internal abstract class Hash : IHash
    {
        private const string CloneNotYetImplemented = "Clone not yet implemented for '{0}'";
        private const string FileNotExist = "Specified file not found";
        private const string IndexOutOfRange = "Current index is out of range";
        private const string InvalidBufferSize = "'BufferSize' must be greater than zero";
        private const string AsyncOperationCancelled = "Async operation was cancelled by caller {0}";

        private const int InternalBufferSize = 64 * 1024; // 64Kb

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
                if (value <= 0) throw new ArgumentOutOfRangeHashLibException(InvalidBufferSize);
                _bufferSize = value;
            }
        }

        public void TransformBytes(byte[] data, int index)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            Debug.Assert(index >= 0);
            var size = data.Length - index;
            Debug.Assert(size >= 0);
            TransformBytes(data, index, size);
        }

        public void TransformBytes(byte[] data)
        {
            TransformBytes(data, 0, data?.Length ?? 0);
        }

        public void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            TransformBytes(data.ToArray());
        }

        public void TransformString(string data, Encoding encoding)
        {
            TransformBytes(Converters.ConvertStringToBytes(data, encoding));
        }

        public unsafe void TransformUntyped(void* data, long length)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            var dataPtrStart = (byte*) data;
            var bufferSize = BufferSize > length ? InternalBufferSize : BufferSize; // Sanity Check
            var buffer = new byte[bufferSize];

            fixed (byte* bufferPtrStart = buffer)
            {
                var dataPtrEnd = dataPtrStart + length;

                while (dataPtrStart < dataPtrEnd)
                    if (dataPtrEnd - dataPtrStart >= bufferSize)
                    {
                        PointerUtils.MemMove(bufferPtrStart, dataPtrStart, bufferSize);
                        TransformBytes(buffer);
                        dataPtrStart += bufferSize;
                    }
                    else
                    {
                        var remaining = (int) (dataPtrEnd - dataPtrStart);
                        PointerUtils.MemMove(bufferPtrStart, dataPtrStart, remaining);
                        TransformBytes(buffer, 0, remaining);
                        break;
                    }
            }
        }

        public void TransformStream(Stream stream, long length = -1)
        {
            if (stream == null) throw new ArgumentNullHashLibException(nameof(stream));
            Debug.Assert(length == -1 || length > 0);

            var bufferSize = BufferSize;
            if (stream.CanSeek)
            {
                if (length > -1)
                    if (stream.Position + length > stream.Length)
                        throw new IndexOutOfRangeHashLibException(IndexOutOfRange);

                if (stream.Position >= stream.Length)
                    return;
                bufferSize = BufferSize > stream.Length ? InternalBufferSize : BufferSize; // Sanity Check
            }

            var buffer = new byte[bufferSize];
            int read;
            if (length == -1)
            {
                while ((read = stream.Read(buffer, 0, bufferSize)) > 0)
                {
                    TransformBytes(buffer, 0, read);
                }
            }
            else
            {
                long totalRead = 0;
                while ((read = stream.Read(buffer, 0, bufferSize)) > 0)
                {
                    if (totalRead + read >= length)
                    {
                        TransformBytes(buffer, 0, (int) (length - totalRead));
                        break;
                    }

                    TransformBytes(buffer, 0, read);
                    totalRead += read;
                }
            }
        }

        public async Task TransformStreamAsync(Stream stream, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (stream == null) throw new ArgumentNullHashLibException(nameof(stream));
            Debug.Assert(length == -1 || length > 0);

            var bufferSize = BufferSize;
            if (stream.CanSeek)
            {
                if (length > -1)
                    if (stream.Position + length > stream.Length)
                        throw new IndexOutOfRangeHashLibException(IndexOutOfRange);

                if (stream.Position >= stream.Length)
                    return;
                bufferSize = BufferSize > stream.Length ? InternalBufferSize : BufferSize; // Sanity Check
            }

            var buffer = new byte[bufferSize];
            int read;
            if (length == -1)
            {
                while ((read = await stream.ReadAsync(buffer, 0, bufferSize, cancellationToken)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    TransformBytes(buffer, 0, read);
                }
            }
            else
            {
                long totalRead = 0;
                while ((read = await stream.ReadAsync(buffer, 0, bufferSize, cancellationToken)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (totalRead + read >= length)
                    {
                        TransformBytes(buffer, 0, (int) (length - totalRead));
                        break;
                    }

                    TransformBytes(buffer, 0, read);
                    totalRead += read;
                }
            }
        }

        public void TransformFile(string fileName, long from = 0, long length = -1)
        {
            if (fileName == null) throw new ArgumentNullHashLibException(nameof(fileName));
            Debug.Assert(from >= 0);
            Debug.Assert(length == -1 || length > 0);

            FileStream source = null;
            if (File.Exists(fileName))
                try
                {
                    source = new FileStream(fileName,
                        FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize,
                        FileOptions.SequentialScan);

                    source.Seek(from, SeekOrigin.Begin);
                    TransformStream(source, length);
                }
                catch (IOException ioException)
                {
                    throw new IOHashLibException(ioException.Message);
                }
                finally
                {
                    source?.Flush();
                    source?.Dispose();
                }
            else
                throw new FileNotFoundHashLibException(FileNotExist);
        }

        public async Task TransformFileAsync(string fileName, long from = 0, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (fileName == null) throw new ArgumentNullHashLibException(nameof(fileName));
            Debug.Assert(from >= 0);
            Debug.Assert(length == -1 || length > 0);

            FileStream source = null;
            if (File.Exists(fileName))
                try
                {
                    source = new FileStream(fileName,
                        FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize,
                        FileOptions.SequentialScan | FileOptions.Asynchronous);

                    source.Seek(from, SeekOrigin.Begin);
                    await TransformStreamAsync(source, length, cancellationToken);
                }
                catch (IOException ioException)
                {
                    throw new IOHashLibException(ioException.Message);
                }
                catch (OperationCanceledException canceledException)
                {
                    throw new OperationCanceledException(string.Format(AsyncOperationCancelled,
                        canceledException.Message));
                }
                finally
                {
                    if (source != null)
                    {
                        await source.FlushAsync(cancellationToken);
                        await source.DisposeAsync();
                    }
                }
            else
                throw new FileNotFoundHashLibException(FileNotExist);
        }

        public abstract IHashResult TransformFinal();

        public virtual IHashResult ComputeBytes(byte[] data)
        {
            Initialize();
            TransformBytes(data);
            return TransformFinal();
        }

        public IHashResult ComputeByteSpan(ReadOnlySpan<byte> data)
        {
            Initialize();
            TransformByteSpan(data);
            return TransformFinal();
        }

        public IHashResult ComputeString(string data, Encoding encoding)
        {
            return ComputeBytes(Converters.ConvertStringToBytes(data, encoding));
        }

        public unsafe IHashResult ComputeUntyped(void* data, long length)
        {
            Initialize();
            TransformUntyped(data, length);
            return TransformFinal();
        }

        public IHashResult ComputeStream(Stream stream, long length = -1)
        {
            Initialize();
            TransformStream(stream, length);
            return TransformFinal();
        }

        public async Task<IHashResult> ComputeStreamAsync(Stream stream, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            Initialize();
            await TransformStreamAsync(stream, length, cancellationToken);
            return TransformFinal();
        }

        public IHashResult ComputeFile(string fileName, long from = 0, long length = -1)
        {
            Initialize();
            TransformFile(fileName, from, length);
            return TransformFinal();
        }

        public async Task<IHashResult> ComputeFileAsync(string fileName, long from = 0, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            Initialize();
            await TransformFileAsync(fileName, from, length, cancellationToken);
            return TransformFinal();
        }

        public virtual IHash Clone() =>
            throw new NotImplementedHashLibException(string.Format(CloneNotYetImplemented, Name));

        public override string ToString() => Name;

        public abstract void Initialize();

        public abstract void TransformBytes(byte[] data, int index, int length);
    }
}