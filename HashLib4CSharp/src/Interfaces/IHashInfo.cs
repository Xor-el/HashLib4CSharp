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

namespace HashLib4CSharp.Interfaces
{
    internal interface ITransformBlock
    {
    }

    internal interface IBlockHash : IHash
    {
    }

    internal interface INonBlockHash
    {
    }

    public interface IChecksum : IHash
    {
    }

    internal interface ICrypto : IHash
    {
    }

    internal interface ICryptoBuiltIn : ICrypto
    {
    }

    internal interface ICryptoNotBuiltIn : ICrypto
    {
    }

    public interface IWithKey : IHash
    {
        byte[] Key { get; set; }
        int KeyLength { get; }
    }

    public interface IHashWithKey : IWithKey
    {
    }

    internal interface IHash32 : IHash
    {
    }

    internal interface IHash64 : IHash
    {
    }

    internal interface IHash128 : IHash
    {
    }
}