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
    /// There are two versions, 16 and 19. 19 is 5%-15% slower but fixes a vulnerability
    /// where an attacker could take advantage of short time spans where memory blocks
    /// were not used to reduce the overall memory cost by up to a factor of about 3.5.
    /// </summary>
    public enum Argon2Version
    {
        /// <summary>
        /// For Argon2 versions 1.2.1 or earlier.
        /// </summary>
        Sixteen = 0x10,

        /// <summary>
        /// For Argon2 version 1.3.
        /// </summary>
        Nineteen = 0x13
    }
}