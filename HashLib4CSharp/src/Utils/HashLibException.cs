/*
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
{ *                             HashLib4CSharp Library                              * }
{ *                      Copyright (c) 2020 Ugochukwu Mmaduekwe                     * }
{ *                 GitHub Profile URL <https://github.com/Xor-el>                  * }

{ *  Distributed under the MIT software license, see the accompanying LICENSE file  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *   This library was sponsored by Sphere 10 Software (https://www.sphere10.com)   * }
{ *         for the purposes of supporting the XXX (https://YYY) project.           * }
{ *                                                                                 * }
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
*/

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