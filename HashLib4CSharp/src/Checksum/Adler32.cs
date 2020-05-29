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
using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Checksum
{
    internal sealed class Adler32 : Hash, IChecksum, IHash32, ITransformBlock
    {
        private const uint ModAdler = 65521;
        private uint _a, _b;

        public Adler32()
            : base(4, 1)
        {
        }

        public override IHash Clone() => new Adler32 {_a = _a, _b = _b, BufferSize = BufferSize};

        public override void Initialize()
        {
            _a = 1;
            _b = 0;
        }

        public override IHashResult TransformFinal()
        {
            var buffer = new byte[HashSize];
            Converters.ReadUInt32AsBytesBE((_b << 16) | _a, buffer, 0);
            var result = new HashResult(buffer);
            Initialize();
            return result;
        }

        public override void TransformBytes(byte[] data, int index, int length)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            Debug.Assert(index >= 0);
            Debug.Assert(length >= 0);
            Debug.Assert(index + length <= data.Length);

            var a = _a;
            var b = _b;
            while (length > 0)
            {
                // We can defer the modulo operation:
                // a maximally grows from 65521 to 65521 + 255 * 3800
                // b maximally grows by 3800 * median(a) = 2090079800 < 2^31
                var n = 3800;
                if (n > length)
                    n = length;

                length -= n;

                while (n - 1 >= 0)
                {
                    a += data[index];
                    b += a;
                    index++;
                    n--;
                }

                a %= ModAdler;
                b %= ModAdler;
            }

            _a = a;
            _b = b;
        }
    }
}