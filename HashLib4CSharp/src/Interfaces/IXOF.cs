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
    public interface IXOF : IHash
    {
        ulong XofSizeInBits { get; set; }

        void DoOutput(Span<byte> dest);
    }

    public static class IXOFExtensions
    {
        private const string OutputBufferTooShort = "Output buffer too short";
        public static void DoOutput(this IXOF xof, byte[] dest, int destOffset, int outputLength)
        {
            if (dest == null) throw new ArgumentNullException(nameof(dest));

            if (dest.Length - destOffset < outputLength)
                throw new ArgumentException(OutputBufferTooShort);

            xof.DoOutput(dest.AsSpan().Slice(destOffset, outputLength));
        }
    }
}