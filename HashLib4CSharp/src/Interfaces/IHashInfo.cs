
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

    internal interface IHash16 : IHash
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