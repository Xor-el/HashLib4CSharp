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
    public interface IMAC : IHash
    {
        byte[] Key { get; set; }
        void Clear();
    }

    public interface IMACNotBuiltIn : IMAC
    {
    }

    public interface IHMAC : IMACNotBuiltIn
    {
    }

    public interface IHMACNotBuiltIn : IHMAC
    {
        byte[] WorkingKey { get; }
    }

    public interface IKMAC : IMACNotBuiltIn
    {
    }

    public interface IKMACNotBuiltIn : IKMAC
    {
    }

    public interface IBlake2MAC : IMACNotBuiltIn
    {
    }

    public interface IBlake2BMAC : IBlake2MAC
    {
    }

    public interface IBlake2BMACNotBuiltIn : IBlake2BMAC
    {
    }

    public interface IBlake2SMAC : IBlake2MAC
    {
    }

    public interface IBlake2SMACNotBuiltIn : IBlake2SMAC
    {
    }
}