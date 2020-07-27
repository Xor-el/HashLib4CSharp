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

namespace HashLib4CSharp.Interfaces
{
    public interface IKDF
    {
        /// <summary>
        /// Clear sensitive materials from memory
        /// </summary>
        void Clear();

        /// <summary>
        /// Returns the pseudo-random bytes for this object.
        /// </summary>
        /// <param name="byteCount">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        byte[] GetBytes(int byteCount);

        Task<byte[]> GetBytesAsync(int byteCount, CancellationToken cancellationToken = default);
        string Name { get; }
        string ToString();
    }

    public interface IKDFNotBuiltIn : IKDF
    {
        IKDFNotBuiltIn Clone();
    }

    public interface IPBKDF2HMAC : IKDFNotBuiltIn
    {
    }

    public interface IPBKDF2HMACNotBuiltIn : IPBKDF2HMAC
    {
    }

    public interface IPBKDFArgon2 : IKDFNotBuiltIn
    {
    }

    public interface IPBKDFArgon2NotBuiltIn : IPBKDFArgon2
    {
    }

    public interface IPBKDFScrypt : IKDFNotBuiltIn
    {
    }

    public interface IPBKDFScryptNotBuiltIn : IPBKDFScrypt
    {
    }

    public interface IPBKDFBlake3 : IKDFNotBuiltIn
    {
    }

    public interface IPBKDFBlake3NotBuiltIn : IPBKDFBlake3
    {
    }
}