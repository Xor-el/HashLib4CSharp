using System;

namespace HashLib4CSharp.Utils
{
    public class HashLibException : Exception
    {
        protected HashLibException(string message) : base(message)
        {
        }
    }

    public sealed class NullReferenceHashLibException : HashLibException
    {
        internal NullReferenceHashLibException(string message) : base(message)
        {
        }
    }

    public sealed class InvalidOperationHashLibException : HashLibException
    {
        internal InvalidOperationHashLibException(string message) : base(message)
        {
        }
    }

    public sealed class IndexOutOfRangeHashLibException : HashLibException
    {
        internal IndexOutOfRangeHashLibException(string message) : base(message)
        {
        }
    }

    public class ArgumentHashLibException : HashLibException
    {
        internal ArgumentHashLibException(string message) : base(message)
        {
        }
    }

    public sealed class ArgumentInvalidHashLibException : ArgumentHashLibException
    {
        internal ArgumentInvalidHashLibException(string message) : base(message)
        {
        }
    }

    public sealed class ArgumentNullHashLibException : ArgumentHashLibException
    {
        public ArgumentNullHashLibException(string message) : base(message)
        {
        }
    }

    public sealed class ArgumentOutOfRangeHashLibException : ArgumentHashLibException
    {
        internal ArgumentOutOfRangeHashLibException(string message) : base(message)
        {
        }
    }

    public sealed class NotImplementedHashLibException : HashLibException
    {
        internal NotImplementedHashLibException(string message) : base(message)
        {
        }
    }

    public class IOHashLibException : HashLibException
    {
        internal IOHashLibException(string message) : base(message)
        {
        }
    }

    public sealed class FileNotFoundHashLibException : IOHashLibException
    {
        internal FileNotFoundHashLibException(string message) : base(message)
        {
        }
    }
}