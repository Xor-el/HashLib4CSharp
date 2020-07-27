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
    internal static class Blake2SErrorStrings
    {
        internal const string InvalidHashSize = "HashSize must be restricted to one of the following [1 .. 32], '{0}'";
        internal const string InvalidKeyLength = "Key length must not be greater than 32, '{0}'";
        internal const string InvalidPersonalizationLength = "Personalization length must be equal to 8, '{0}'";
        internal const string InvalidSaltLength = "Salt length must be equal to 8, '{0}'";
        internal const string InvalidInnerHashSize = "treeConfig InnerHashSize must be between [0 .. 32], '{0}'";
        internal const string InvalidMaxDepth = "MaxDepth must be between [1 .. 255], '{0}'";
        internal const string InvalidNodeOffset = "NodeOffset must be between [0 .. (2^48-1)], '{0}'";
    }

    public sealed class Blake2SConfig
    {
        private int _hashSize;
        private byte[] _key, _salt, _personalization;

        public int HashSize
        {
            get => _hashSize;
            set
            {
                if (value < 1 || value > 32)
                    throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidHashSize,
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
                if (keyLength > 32)
                    throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidKeyLength,
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
                if (saltLength != 0 && saltLength != 8)
                    throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidSaltLength,
                        saltLength));
                _salt = ArrayUtils.Clone(value);
            }
        }

        public byte[] Personalization
        {
            get => _personalization != null ? ArrayUtils.Clone(_personalization) : null;
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                var personalizationLength = value.Length;
                if (personalizationLength != 0 && personalizationLength != 8)
                    throw new ArgumentException(
                        string.Format(Blake2SErrorStrings.InvalidPersonalizationLength, personalizationLength));
                _personalization = ArrayUtils.Clone(value);
            }
        }

        public Blake2SConfig(int hashSize)
        {
            HashSize = hashSize;
            _key = new byte[0];
            _salt = new byte[0];
            _personalization = new byte[0];
        }

        internal Blake2SConfig(HashSize hashSize = Enum.HashSize.HashSize256) : this((int) hashSize)
        {
        }

        ~Blake2SConfig()
        {
            Clear();
        }

        public void Clear()
        {
            ArrayUtils.ZeroFill(_key);
            ArrayUtils.ZeroFill(_salt);
            ArrayUtils.ZeroFill(_personalization);
        }

        public Blake2SConfig Clone() =>
            new Blake2SConfig
            {
                _hashSize = _hashSize,
                _key = ArrayUtils.Clone(_key),
                _salt = ArrayUtils.Clone(_salt),
                _personalization = ArrayUtils.Clone(_personalization)
            };

        public static Blake2SConfig DefaultConfig => new Blake2SConfig();

        public static Blake2SConfig CreateBlake2SConfig(int hashSize) => new Blake2SConfig(hashSize);
    }

    public sealed class Blake2STreeConfig
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
            set
            {
                if (value > ((ulong) 1 << 48) - 1)
                    throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidNodeOffset,
                        value));
                _nodeOffset = value;
            }
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
                    throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidMaxDepth,
                        value));
                _maxDepth = value;
            }
        }

        public byte InnerHashSize
        {
            get => _innerHashSize;
            set
            {
                if (value > 32)
                    throw new ArgumentException(
                        string.Format(Blake2SErrorStrings.InvalidInnerHashSize, value));
                _innerHashSize = value;
            }
        }

        public Blake2STreeConfig()
        {
            _fanOut = 0;
            _maxDepth = 0;
            _leafSize = 32;
            _nodeOffset = 0;
            _nodeDepth = 0;
            _innerHashSize = 32;
            _isLastNode = false;
        }

        public Blake2STreeConfig Clone() =>
            new Blake2STreeConfig
            {
                _fanOut = _fanOut,
                _innerHashSize = _innerHashSize,
                _maxDepth = _maxDepth,
                _nodeDepth = _nodeDepth,
                _leafSize = _leafSize,
                _nodeOffset = _nodeOffset,
                _isLastNode = _isLastNode
            };

        internal static Blake2STreeConfig SequentialTreeConfig => new Blake2STreeConfig
        {
            _fanOut = 1,
            _maxDepth = 1,
            _leafSize = 0,
            _nodeOffset = 0,
            _nodeDepth = 0,
            _innerHashSize = 0,
            _isLastNode = false
        };

        public static Blake2STreeConfig DefaultTreeConfig => new Blake2STreeConfig();
    }

    internal static class Blake2SIvBuilder
    {
        private static void VerifyConfigS(Blake2SConfig config, Blake2STreeConfig treeConfig, bool isSequential)
        {
            if (config.HashSize < 1 || config.HashSize > 32)
                throw new ArgumentException(
                    string.Format(Blake2SErrorStrings.InvalidHashSize, config.HashSize));

            if (config.Key.Length != 0)
            {
                var keyLength = config.Key.Length;
                if (keyLength > 32)
                    throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidKeyLength,
                        keyLength));
            }

            if (config.Salt.Length != 0)
            {
                var saltLength = config.Salt.Length;
                if (saltLength != 8)
                    throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidSaltLength,
                        saltLength));
            }

            if (config.Personalization.Length != 0)
            {
                var personalizationLength = config.Personalization.Length;
                if (personalizationLength != 8)
                    throw new ArgumentException(
                        string.Format(Blake2SErrorStrings.InvalidPersonalizationLength, personalizationLength));
            }

            if (treeConfig == null) return;
            if (isSequential & treeConfig.InnerHashSize != 0)
            {
                throw new ArgumentException("treeConfig.InnerHashSize");
            }

            if (treeConfig.InnerHashSize > 32)
                throw new ArgumentException(string.Format(Blake2SErrorStrings.InvalidInnerHashSize,
                    treeConfig.InnerHashSize));
        }

        internal static unsafe Span<uint> ConfigB(Blake2SConfig config, ref Blake2STreeConfig treeConfig)
        {
            var isSequential = treeConfig == null;

            if (isSequential)
                treeConfig = Blake2STreeConfig.SequentialTreeConfig;

            VerifyConfigS(config, treeConfig, isSequential);

            Span<byte> buffer = stackalloc byte[32];

            buffer[0] = (byte) config.HashSize;
            buffer[1] = (byte) config.Key.Length;

            if (treeConfig != null)
            {
                buffer[2] = treeConfig.FanOut;
                buffer[3] = treeConfig.MaxDepth;
                Converters.ReadUInt32AsBytesLE(treeConfig.LeafSize, buffer.Slice(4));
                buffer[8] = (byte) treeConfig.NodeOffset;
                buffer[9] = (byte) (treeConfig.NodeOffset >> 8);
                buffer[10] = (byte) (treeConfig.NodeOffset >> 16);
                buffer[11] = (byte) (treeConfig.NodeOffset >> 24);
                buffer[12] = (byte) (treeConfig.NodeOffset >> 32);
                buffer[13] = (byte) (treeConfig.NodeOffset >> 40);
                buffer[14] = treeConfig.NodeDepth;
                buffer[15] = treeConfig.InnerHashSize;
            }

            if (config.Salt.Length != 0)
            {
                fixed (byte* src = config.Salt, dest = &buffer[16])
                {
                    PointerUtils.MemMove(dest, src, 8);
                }
            }

            if (config.Personalization.Length != 0)
            {
                fixed (byte* src = config.Personalization, dest = &buffer[24])
                {
                    PointerUtils.MemMove(dest, src, 8);
                }
            }

            Span<uint> result = new uint[8];
            fixed (byte* src = buffer)
            {
                fixed (uint* dest = result)
                {
                    Converters.le32_copy(src, 0, dest, 0,
                        buffer.Length);
                }
            }

            return result;
        }
    }
}