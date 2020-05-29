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
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HashLib4CSharp.Interfaces
{
    public interface IHash
    {
        string Name { get; }
        int BlockSize { get; }
        int HashSize { get; }
        int BufferSize { get; set; }

        void Initialize();

        void TransformBytes(byte[] data, int index, int length);

        void TransformBytes(byte[] data, int index);

        void TransformBytes(byte[] data);

        void TransformByteSpan(ReadOnlySpan<byte> data);

        void TransformString(string data, Encoding encoding);

        unsafe void TransformUntyped(void* data, long length);

        void TransformStream(Stream stream, long length = -1);

        Task TransformStreamAsync(Stream stream, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken));

        void TransformFile(string fileName, long from = 0, long length = -1);

        Task TransformFileAsync(string fileName, long from = 0, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken));

        IHashResult TransformFinal();

        IHashResult ComputeBytes(byte[] data);

        IHashResult ComputeByteSpan(ReadOnlySpan<byte> data);

        IHashResult ComputeString(string data, Encoding encoding);

        unsafe IHashResult ComputeUntyped(void* data, long length);

        IHashResult ComputeStream(Stream stream, long length = -1);

        Task<IHashResult> ComputeStreamAsync(Stream stream, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken));

        IHashResult ComputeFile(string fileName, long from = 0, long length = -1);

        Task<IHashResult> ComputeFileAsync(string fileName, long from = 0, long length = -1,
            CancellationToken cancellationToken = default(CancellationToken));

        IHash Clone();

        string ToString();
    }
}