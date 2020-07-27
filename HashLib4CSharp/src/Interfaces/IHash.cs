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
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Base;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Interfaces
{
    public interface IHash
    {
        string Name { get; }
        int BlockSize { get; }
        int HashSize { get; }
        int BufferSize { get; set; }
        void Initialize();
        void TransformByteSpan(ReadOnlySpan<byte> data);
        IHashResult TransformFinal();
        IHash Clone();
        string ToString();
    }

    public static class IHashExtensions
    {
        private const string FileNotExist = "Specified file not found";
        private const string IndexOutOfRange = "Current index is out of range";
        private const string AsyncOperationCancelled = "Async operation was cancelled by caller {0}";

        private const int InternalBufferSize = Hash.InternalBufferSize;

        public static void TransformBytes(this IHash hasher, byte[] data)
        {
            TransformBytes(hasher, data, 0, data?.Length ?? 0);
        }
        public static void TransformBytes(this IHash hasher, byte[] data, int index)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            Debug.Assert(index >= 0);
            var size = data.Length - index;
            Debug.Assert(size >= 0);
            TransformBytes(hasher, data, index, size);
        }

        public static void TransformBytes(this IHash hasher, byte[] data, int index, int length)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            Debug.Assert(index >= 0);
            Debug.Assert(length >= 0);
            hasher.TransformByteSpan(data.AsSpan(index, length));
        }

        public static void TransformString(this IHash hasher, string data, Encoding encoding)
        {
            hasher.TransformBytes(Converters.ConvertStringToBytes(data, encoding));
        }

        public static unsafe void TransformUntyped(this IHash hasher, void* data, long length)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            var dataPtrStart = (byte*)data;
            var bufferSize = hasher.BufferSize > length ? InternalBufferSize : hasher.BufferSize; // Sanity Check
            Span<byte> buffer = bufferSize > InternalBufferSize ? new byte[bufferSize] : stackalloc byte[bufferSize];
            fixed (byte* bufferPtrStart = buffer)
            {
                var dataPtrEnd = dataPtrStart + length;

                while (dataPtrStart < dataPtrEnd)
                    if (dataPtrEnd - dataPtrStart >= bufferSize)
                    {
                        PointerUtils.MemMove(bufferPtrStart, dataPtrStart, bufferSize);
                        hasher.TransformByteSpan(buffer);
                        dataPtrStart += bufferSize;
                    }
                    else
                    {
                        var remaining = (int)(dataPtrEnd - dataPtrStart);
                        PointerUtils.MemMove(bufferPtrStart, dataPtrStart, remaining);
                        hasher.TransformByteSpan(buffer.Slice(0, remaining));
                        break;
                    }
            }
        }

        public static void TransformStream(this IHash hasher, Stream stream, long length = -1)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            Debug.Assert(length == -1 || length > 0);

            var bufferSize = hasher.BufferSize;
            if (stream.CanSeek)
            {
                if (length > -1)
                    if (stream.Position + length > stream.Length)
                        throw new IndexOutOfRangeException(IndexOutOfRange);

                if (stream.Position >= stream.Length)
                    return;
                bufferSize = hasher.BufferSize > stream.Length ? InternalBufferSize : hasher.BufferSize; // Sanity Check
            }

            Span<byte> buffer = bufferSize > InternalBufferSize ? new byte[bufferSize] : stackalloc byte[bufferSize];
            int read;
            if (length == -1)
            {
                while ((read = stream.Read(buffer.Slice(0, bufferSize))) > 0)
                {
                    hasher.TransformByteSpan(buffer.Slice(0, read));
                }
            }
            else
            {
                long totalRead = 0;
                while ((read = stream.Read(buffer.Slice(0, bufferSize))) > 0)
                {
                    if (totalRead + read >= length)
                    {
                        hasher.TransformByteSpan(buffer.Slice(0, (int)(length - totalRead)));
                        break;
                    }

                    hasher.TransformByteSpan(buffer.Slice(0, read));
                    totalRead += read;
                }
            }
        }

        public static async Task TransformStreamAsync(this IHash hasher, Stream stream, long length = -1, CancellationToken cancellationToken = default)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            Debug.Assert(length == -1 || length > 0);

            var bufferSize = hasher.BufferSize;
            if (stream.CanSeek)
            {
                if (length > -1)
                    if (stream.Position + length > stream.Length)
                        throw new IndexOutOfRangeException(IndexOutOfRange);

                if (stream.Position >= stream.Length)
                    return;
                bufferSize = hasher.BufferSize > stream.Length ? InternalBufferSize : hasher.BufferSize; // Sanity Check
            }

            var buffer = new byte[bufferSize];
            int read;
            if (length == -1)
            {
                while ((read = await stream.ReadAsync(buffer, 0, bufferSize, cancellationToken)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    hasher.TransformBytes(buffer, 0, read);
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
                        hasher.TransformBytes(buffer, 0, (int)(length - totalRead));
                        break;
                    }

                    hasher.TransformBytes(buffer, 0, read);
                    totalRead += read;
                }
            }
        }

        public static void TransformFile(this IHash hasher, string fileName, long from = 0, long length = -1)
        {
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            Debug.Assert(from >= 0);
            Debug.Assert(length == -1 || length > 0);

            FileStream source = null;
            if (File.Exists(fileName))
                try
                {
                    source = new FileStream(fileName,
                        FileMode.Open, FileAccess.Read, FileShare.Read, hasher.BufferSize, FileOptions.SequentialScan);

                    source.Seek(from, SeekOrigin.Begin);
                    hasher.TransformStream(source, length);
                }
                finally
                {
                    source?.Flush();
                    source?.Dispose();
                }
            else
                throw new FileNotFoundException(FileNotExist);
        }

        public static async Task TransformFileAsync(this IHash hasher, string fileName, long from = 0, long length = -1, CancellationToken cancellationToken = default)
        {
            if (fileName == null) throw new ArgumentNullException(nameof(fileName));
            Debug.Assert(from >= 0);
            Debug.Assert(length == -1 || length > 0);

            FileStream source = null;
            if (File.Exists(fileName))
                try
                {
                    source = new FileStream(fileName,
                        FileMode.Open, FileAccess.Read, FileShare.Read, hasher.BufferSize, FileOptions.SequentialScan | FileOptions.Asynchronous);

                    source.Seek(from, SeekOrigin.Begin);
                    await hasher.TransformStreamAsync(source, length, cancellationToken);
                }
                catch (OperationCanceledException canceledException)
                {
                    throw new OperationCanceledException(string.Format(AsyncOperationCancelled, canceledException.Message));
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
                throw new FileNotFoundException(FileNotExist);
        }

        public static IHashResult ComputeBytes(this IHash hasher, byte[] data)
        {
            hasher.Initialize();
            hasher.TransformBytes(data);
            return hasher.TransformFinal();
        }

        public static IHashResult ComputeByteSpan(this IHash hasher, ReadOnlySpan<byte> data)
        {
            hasher.Initialize();
            hasher.TransformByteSpan(data);
            return hasher.TransformFinal();
        }

        public static IHashResult ComputeString(this IHash hasher, string data, Encoding encoding)
        {
            return hasher.ComputeBytes(Converters.ConvertStringToBytes(data, encoding));
        }

        public static unsafe IHashResult ComputeUntyped(this IHash hasher, void* data, long length)
        {
            hasher.Initialize();
            hasher.TransformUntyped(data, length);
            return hasher.TransformFinal();
        }

        public static IHashResult ComputeStream(this IHash hasher, Stream stream, long length = -1)
        {
            hasher.Initialize();
            hasher.TransformStream(stream, length);
            return hasher.TransformFinal();
        }

        public static async Task<IHashResult> ComputeStreamAsync(this IHash hasher, Stream stream, long length = -1, CancellationToken cancellationToken = default)
        {
            hasher.Initialize();
            await hasher.TransformStreamAsync(stream, length, cancellationToken);
            return hasher.TransformFinal();
        }

        public static IHashResult ComputeFile(this IHash hasher, string fileName, long from = 0, long length = -1)
        {
            hasher.Initialize();
            hasher.TransformFile(fileName, from, length);
            return hasher.TransformFinal();
        }

        public static async Task<IHashResult> ComputeFileAsync(this IHash hasher, string fileName, long from = 0, long length = -1, CancellationToken cancellationToken = default)
        {
            hasher.Initialize();
            await hasher.TransformFileAsync(fileName, from, length, cancellationToken);
            return hasher.TransformFinal();
        }


    }
}