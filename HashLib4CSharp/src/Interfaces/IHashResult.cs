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