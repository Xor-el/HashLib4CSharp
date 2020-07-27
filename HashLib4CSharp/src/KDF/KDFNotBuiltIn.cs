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

using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Interfaces;

namespace HashLib4CSharp.KDF
{
    internal abstract class KDFNotBuiltIn : IKDFNotBuiltIn
    {
        public abstract void Clear();

        public abstract byte[] GetBytes(int byteCount);

        public abstract Task<byte[]> GetBytesAsync(int byteCount,
            CancellationToken cancellationToken = default);

        public abstract string Name { get; }

        public abstract override string ToString();

        public abstract IKDFNotBuiltIn Clone();
    }
}