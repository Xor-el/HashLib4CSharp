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

namespace HashLib4CSharp.Interfaces
{
    public interface IHashResult
    {
        byte[] GetBytes();

        byte GetUInt8();

        ushort GetUInt16();

        uint GetUInt32();

        int GetInt32();

        ulong GetUInt64();

        string ToString(bool group);

        int GetHashCode();

        bool Equals(IHashResult hashResult);

        bool Equals(object obj);

        string ToString();

        string ToBase64String(Base64FormattingOptions options = Base64FormattingOptions.None);
    }
}