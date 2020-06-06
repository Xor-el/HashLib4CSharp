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

namespace HashLib4CSharp.Enum
{
    /// <summary>
    /// Argon2 can hash in three different ways, data-dependent, data-independent and hybrid.
    /// </summary>
    /// <remarks>
    /// <para>
    /// From the Argon2 paper:
    /// </para>
    /// <para>
    /// Argon2 has three variants: Argon2d [data-dependent], Argon2i [data-independent] and Argon2id [hybrid of both].
    /// Argon2d is faster and uses data-depending memory access, which makes it suitable
    /// for crypto currencies and applications with no threats from side-channel timing
    /// attacks. Argon2i uses data-independent memory access, which is preferred for
    /// password hashing and password-based key derivation. Argon2i is slower as it
    /// makes more passes over the memory to protect from tradeoff attacks.
    /// </para>
    /// <para>
    ///
    /// </para>
    /// </remarks>
    public enum Argon2Type
    {
        /// <summary>
        /// Use data-dependent addressing. This is faster but susceptible to
        /// side-channel attacks.
        /// </summary>
        DataDependentAddressing = 0,

        /// <summary>
        /// Use data-independent addressing. This is slower and recommended for password
        /// hashing and password-based key derivation.
        /// </summary>
        DataIndependentAddressing = 1,

        /// <summary>
        /// Use a hybrid of data-dependent and data-independent addressing.
        /// </summary>
        HybridAddressing = 2
    }
}