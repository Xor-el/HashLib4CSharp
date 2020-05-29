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
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Base
{
    internal sealed class HashResult : IHashResult
    {
        private const string ImpossibleRepresentationInt32 =
            "Current Data Structure cannot be Represented as an 'Int32' Type.";

        private const string ImpossibleRepresentationUInt8 =
            "Current Data Structure cannot be Represented as an 'UInt8' Type.";

        private const string ImpossibleRepresentationUInt16 =
            "Current Data Structure cannot be Represented as an 'UInt16' Type.";

        private const string ImpossibleRepresentationUInt32 =
            "Current Data Structure cannot be Represented as an 'UInt32' Type.";

        private const string ImpossibleRepresentationUInt64 =
            "Current Data Structure cannot be Represented as an 'UInt64' Type.";

        private readonly byte[] _hash;

        internal HashResult(byte hash)
        {
            _hash = new[] {hash};
        }

        internal HashResult(ushort hash)
        {
            _hash = new[] {(byte) (hash >> 8), (byte) hash};
        }

        internal HashResult(int hash)
        {
            _hash = new[]
                {(byte) Bits.Asr32(hash, 24), (byte) Bits.Asr32(hash, 16), (byte) Bits.Asr32(hash, 8), (byte) hash};
        }

        internal HashResult(uint hash)
        {
            _hash = new byte[sizeof(uint)];
            Converters.ReadUInt32AsBytesBE(hash, _hash, 0);
        }

        internal HashResult(ulong hash)
        {
            _hash = new byte[sizeof(ulong)];
            Converters.ReadUInt64AsBytesBE(hash, _hash, 0);
        }

        internal HashResult(byte[] hash)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            _hash = hash.Length != 0 ? ArrayUtils.Clone(hash) : new byte[0];
        }


        public byte[] GetBytes() => ArrayUtils.Clone(_hash);

        public int GetInt32() =>
            _hash.Length != 4
                ? throw new InvalidOperationException(ImpossibleRepresentationInt32)
                : (_hash[0] << 24) | (_hash[1] << 16) | (_hash[2] << 8) | _hash[3];

        public byte GetUInt8() =>
            _hash.Length != 1
                ? throw new InvalidOperationException(ImpossibleRepresentationUInt8)
                : _hash[0];

        public ushort GetUInt16() =>
            _hash.Length != 2
                ? throw new InvalidOperationException(ImpossibleRepresentationUInt16)
                : (ushort) ((_hash[0] << 8) | _hash[1]);

        public unsafe uint GetUInt32()
        {
            if (_hash.Length != 4) throw new InvalidOperationException(ImpossibleRepresentationUInt32);
            fixed (byte* src = _hash)
            {
                return Converters.ReadBytesAsUInt32BE(src, 0);
            }
        }

        public unsafe ulong GetUInt64()
        {
            if (_hash.Length != 8) throw new InvalidOperationException(ImpossibleRepresentationUInt64);
            fixed (byte* src = _hash)
            {
                return Converters.ReadBytesAsUInt64BE(src, 0);
            }
        }

        public string ToString(bool group) => Converters.ConvertBytesToHexString(_hash, @group);

        public override string ToString() => ToString(false);

        public string ToBase64String(Base64FormattingOptions options = Base64FormattingOptions.None) =>
            Convert.ToBase64String(_hash, options);

        public bool Equals(IHashResult hashResult) => ArrayUtils.ConstantTimeAreEqual(hashResult.GetBytes(), _hash);

        public override bool Equals(object obj) =>
            obj == null
                ? throw new ArgumentNullException(nameof(obj))
                : obj is HashResult hashResult && hashResult.Equals(this);

        public override int GetHashCode()
        {
            var base64String = Convert.ToBase64String(_hash);

            uint result = 0;
            var index = 0;
            var end = base64String.Length;

            while (index < end)
            {
                result = Bits.RotateLeft32(result, 5);
                result ^= base64String[index];
                index++;
            }

            return (int) result;
        }
    }
}