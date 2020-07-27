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
using HashLib4CSharp.Enum;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Params
{
    internal static class Blake2BErrorStrings
    {
        internal const string InvalidHashSize = "HashSize must be restricted to one of the following [1 .. 64], '{0}'";
        internal const string InvalidKeyLength = "Key length must not be greater than 64, '{0}'";
        internal const string InvalidPersonalizationLength = "Personalization length must be equal to 16, '{0}'";
        internal const string InvalidSaltLength = "Salt length must be equal to 16, '{0}'";
        internal const string InvalidInnerHashSize = "treeConfig InnerHashSize must be between [0 .. 64], '{0}'";
        internal const string InvalidMaxDepth = "MaxDepth must be between [1 .. 255], '{0}'";
    }

    public sealed class Blake2BConfig
    {
        private int _hashSize;
        private byte[] _key, _salt, _personalization;

        public int HashSize
        {
            get => _hashSize;
            set
            {
                if (value < 1 || value > 64)
                    throw new ArgumentException(string.Format(Blake2BErrorStrings.InvalidHashSize,
                        value));
                _hashSize = value;
            }
        }

        public byte[] Key
        {
            get => ArrayUtils.Clone(_key);
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                var keyLength = value.Length;
                if (keyLength > 64)
                    throw new ArgumentException(string.Format(Blake2BErrorStrings.InvalidKeyLength,
                        keyLength));
                _key = ArrayUtils.Clone(value);
            }
        }

        public byte[] Salt
        {
            get => ArrayUtils.Clone(_salt);
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                var saltLength = value.Length;
                if (saltLength != 0 && saltLength != 16)
                    throw new ArgumentException(string.Format(Blake2BErrorStrings.InvalidSaltLength,
                        saltLength));
                _salt = ArrayUtils.Clone(value);
            }
        }

        public byte[] Personalization
        {
            get => ArrayUtils.Clone(_personalization);
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                var personalizationLength = value.Length;
                if (personalizationLength != 0 && personalizationLength != 16)
                    throw new ArgumentException(
                        string.Format(Blake2BErrorStrings.InvalidPersonalizationLength, personalizationLength));
                _personalization = ArrayUtils.Clone(value);
            }
        }

        public Blake2BConfig(int hashSize)
        {
            HashSize = hashSize;
            _key = new byte[0];
            _salt = new byte[0];
            _personalization = new byte[0];
        }

        internal Blake2BConfig(HashSize hashSize = Enum.HashSize.HashSize512) : this((int) hashSize)
        {
        }

        ~Blake2BConfig()
        {
            Clear();
        }

        public void Clear()
        {
            ArrayUtils.ZeroFill(_key);
            ArrayUtils.ZeroFill(_salt);
            ArrayUtils.ZeroFill(_personalization);
        }

        public Blake2BConfig Clone() =>
            new Blake2BConfig
            {
                _hashSize = _hashSize,
                _key = ArrayUtils.Clone(_key),
                _salt = ArrayUtils.Clone(_salt),
                _personalization = ArrayUtils.Clone(_personalization)
            };

        public static Blake2BConfig DefaultConfig => new Blake2BConfig();

        public static Blake2BConfig CreateBlake2BConfig(int hashSize) => new Blake2BConfig(hashSize);
    }

    public sealed class Blake2BTreeConfig
    {
        private byte _innerHashSize, _maxDepth, _fanOut, _nodeDepth;
        private uint _leafSize;
        private ulong _nodeOffset;
        private bool _isLastNode;

        public byte FanOut
        {
            get => _fanOut;
            set => _fanOut = value;
        }

        public byte NodeDepth
        {
            get => _nodeDepth;
            set => _nodeDepth = value;
        }

        public uint LeafSize
        {
            get => _leafSize;
            set => _leafSize = value;
        }

        public ulong NodeOffset
        {
            get => _nodeOffset;
            set => _nodeOffset = value;
        }

        public bool IsLastNode
        {
            get => _isLastNode;
            set => _isLastNode = value;
        }

        public byte MaxDepth
        {
            get => _maxDepth;
            set
            {
                if (value < 1)
                    throw new ArgumentException(string.Format(Blake2BErrorStrings.InvalidMaxDepth,
                        value));
                _maxDepth = value;
            }
        }

        public byte InnerHashSize
        {
            get => _innerHashSize;
            set
            {
                if (value > 64)
                    throw new ArgumentException(
                        string.Format(Blake2BErrorStrings.InvalidInnerHashSize, value));
                _innerHashSize = value;
            }
        }

        public Blake2BTreeConfig()
        {
            _fanOut = 0;
            _maxDepth = 0;
            _leafSize = 64;
            _nodeOffset = 0;
            _nodeDepth = 0;
            _innerHashSize = 64;
            _isLastNode = false;
        }

        public Blake2BTreeConfig Clone() =>
            new Blake2BTreeConfig
            {
                _fanOut = _fanOut,
                _innerHashSize = _innerHashSize,
                _maxDepth = _maxDepth,
                _nodeDepth = _nodeDepth,
                _leafSize = _leafSize,
                _nodeOffset = _nodeOffset,
                _isLastNode = _isLastNode
            };

        internal static Blake2BTreeConfig SequentialTreeConfig => new Blake2BTreeConfig
        {
            _fanOut = 1,
            _maxDepth = 1,
            _leafSize = 0,
            _nodeOffset = 0,
            _nodeDepth = 0,
            _innerHashSize = 0,
            _isLastNode = false
        };

        public static Blake2BTreeConfig DefaultTreeConfig => new Blake2BTreeConfig();
    }

    internal static class Blake2BIvBuilder
    {
        private static void VerifyConfigB(Blake2BConfig config, Blake2BTreeConfig treeConfig, bool isSequential)
        {
            if (config.HashSize < 1 || config.HashSize > 64)
                throw new ArgumentException(
                    string.Format(Blake2SErrorStrings.InvalidHashSize, config.HashSize));

            if (config.Key.Length != 0)
            {
                var keyLength = config.Key.Length;
                if (keyLength > 64)
                    throw new ArgumentException(string.Format(Blake2BErrorStrings.InvalidKeyLength,
                        keyLength));
            }

            if (config.Salt.Length != 0)
            {
                var saltLength = config.Salt.Length;
                if (saltLength != 16)
                    throw new ArgumentException(string.Format(Blake2BErrorStrings.InvalidSaltLength,
                        saltLength));
            }

            if (config.Personalization.Length != 0)
            {
                var personalizationLength = config.Personalization.Length;
                if (personalizationLength != 16)
                    throw new ArgumentException(
                        string.Format(Blake2BErrorStrings.InvalidPersonalizationLength, personalizationLength));
            }

            if (treeConfig == null) return;
            if (isSequential & treeConfig.InnerHashSize != 0)
            {
                throw new ArgumentException("treeConfig.InnerHashSize");
            }

            if (treeConfig.InnerHashSize > 64)
                throw new ArgumentException(string.Format(Blake2BErrorStrings.InvalidInnerHashSize,
                    treeConfig.InnerHashSize));
        }

        internal static unsafe Span<ulong> ConfigB(Blake2BConfig config, ref Blake2BTreeConfig treeConfig)
        {
            var isSequential = treeConfig == null;

            if (isSequential)
                treeConfig = Blake2BTreeConfig.SequentialTreeConfig;

            VerifyConfigB(config, treeConfig, isSequential);

            Span<byte> buffer = stackalloc byte[64];

            buffer[0] = (byte) config.HashSize;
            buffer[1] = (byte) config.Key.Length;

            if (treeConfig != null)
            {
                buffer[2] = treeConfig.FanOut;
                buffer[3] = treeConfig.MaxDepth;
                Converters.ReadUInt32AsBytesLE(treeConfig.LeafSize, buffer.Slice(4));
                Converters.ReadUInt64AsBytesLE(treeConfig.NodeOffset, buffer.Slice(8));
                buffer[16] = treeConfig.NodeDepth;
                buffer[17] = treeConfig.InnerHashSize;
            }

            if (config.Salt.Length != 0)
            {
                fixed (byte* src = config.Salt, dest = &buffer[32])
                {
                    PointerUtils.MemMove(dest, src, 16);
                }
            }

            if (config.Personalization.Length != 0)
            {
                fixed (byte* src = config.Personalization, dest = &buffer[48])
                {
                    PointerUtils.MemMove(dest, src, 16);
                }
            }

            Span<ulong> result = new ulong[8];
            fixed (byte* src = buffer)
            {
                fixed (ulong* dest = result)
                {
                    Converters.le64_copy(src, 0, dest, 0,
                        buffer.Length);
                }
            }

            return result;
        }
    }
}