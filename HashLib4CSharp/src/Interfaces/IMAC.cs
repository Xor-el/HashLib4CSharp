
namespace HashLib4CSharp.Interfaces
{
    public interface IMAC : IHash
    {
        byte[] Key { get; set; }
        void Clear();
    }

    public interface IHMAC : IMAC
    {
    }

    public interface IHMACNotBuiltIn : IHMAC
    {
        byte[] WorkingKey { get; }
    }

    public interface IKMAC : IMAC
    {
    }

    public interface IKMACNotBuiltIn : IKMAC
    {
    }

    public interface IBlake2MAC : IMAC
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