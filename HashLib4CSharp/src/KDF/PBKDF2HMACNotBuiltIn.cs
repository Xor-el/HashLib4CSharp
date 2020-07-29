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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.MAC;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.KDF
{
    internal sealed class PBKDF2HMACNotBuiltIn : KDFNotBuiltIn, IPBKDF2HMACNotBuiltIn
    {
        private IHMACNotBuiltIn _hmacNotBuiltIn;
        private byte[] _password;
        private byte[] _salt;
        private byte[] _buffer;
        private uint _iterations, _block;
        private int _blockSize, _startIndex, _endIndex;

        private const string InvalidByteCount = "byteCount must be a value greater than zero.";
        private const string InvalidIndex = "Invalid start or end index in the internal buffer.";
        private const string IterationTooSmall = "Iteration must be greater than zero.";

        private PBKDF2HMACNotBuiltIn()
        {
        }

        internal PBKDF2HMACNotBuiltIn(IHash underlyingHash, byte[] password,
            byte[] salt, uint iterations)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (iterations <= 0) throw new ArgumentException(IterationTooSmall);

            _password = ArrayUtils.Clone(password);
            _salt = ArrayUtils.Clone(salt);
            var hash = underlyingHash?.Clone() ?? throw new ArgumentNullException(nameof(underlyingHash));
            _hmacNotBuiltIn = HMACNotBuiltIn.CreateHMAC(hash, _password);

            _iterations = iterations;
            _blockSize = _hmacNotBuiltIn.HashSize;
            _buffer = new byte[_blockSize];
            Initialize();
        }

        ~PBKDF2HMACNotBuiltIn()
        {
            Clear();
        }

        public override void Clear()
        {
            ArrayUtils.ZeroFill(_password);
            ArrayUtils.ZeroFill(_salt);
        }

        /// <summary>
        /// Returns the pseudo-random bytes for this object.
        /// </summary>
        /// <param name="byteCount">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        /// <exception cref="ArgumentException">byteCount must be greater than zero.</exception>
        /// <exception cref="IndexOutOfRangeException">invalid start index or end index of internal buffer.</exception>
        public override unsafe byte[] GetBytes(int byteCount)
        {
            if (byteCount <= 0)
                throw new ArgumentException(InvalidByteCount);

            var key = new byte[byteCount];

            var offset = 0;
            var size = _endIndex - _startIndex;
            if (size > 0)
            {
                fixed (byte* bufferPtr = &_buffer[_startIndex], keyPtr = key)
                {
                    if (byteCount >= size)
                    {
                        PointerUtils.MemMove(keyPtr, bufferPtr, size);
                        _startIndex = 0;
                        _endIndex = 0;
                        offset += size;
                    }
                    else
                    {
                        PointerUtils.MemMove(keyPtr, bufferPtr, byteCount);
                        _startIndex += byteCount;
                        Initialize();
                        return key;
                    }
                }
            }

            if (_startIndex != 0 && _endIndex != 0)
                throw new IndexOutOfRangeException(InvalidIndex);

            while (offset < byteCount)
            {
                ReadOnlySpan<byte> block = Func();
                var remainder = byteCount - offset;
                if (remainder > _blockSize)
                {
                    fixed (byte* blockPtr = block, keyPtr = &key[offset])
                    {
                        PointerUtils.MemMove(keyPtr, blockPtr, _blockSize);
                    }

                    offset += _blockSize;
                }
                else
                {
                    if (remainder > 0)
                    {
                        fixed (byte* blockPtr = block, keyPtr = &key[offset])
                        {
                            PointerUtils.MemMove(keyPtr, blockPtr, remainder);
                        }
                    }

                    var remCount = _blockSize - remainder;

                    if (remCount > 0)
                    {
                        fixed (byte* blockPtr = &block[remainder], bufferPtr = &_buffer[_startIndex])
                        {
                            PointerUtils.MemMove(bufferPtr, blockPtr, remCount);
                        }
                    }

                    _endIndex += remCount;
                    Initialize();
                    return key;
                }
            }

            Initialize();
            return key;
        }

        public override async Task<byte[]> GetBytesAsync(int byteCount,
            CancellationToken cancellationToken = default) =>
            await Task.Run(() => GetBytes(byteCount), cancellationToken);

        public override string Name => $"{GetType().Name}({_hmacNotBuiltIn.Name})";

        public override string ToString() => Name;

        public override IKDFNotBuiltIn Clone() =>
            new PBKDF2HMACNotBuiltIn
            {
                _hmacNotBuiltIn = (IHMACNotBuiltIn)_hmacNotBuiltIn.Clone(),
                _password = ArrayUtils.Clone(_password),
                _salt = ArrayUtils.Clone(_salt),
                _buffer = ArrayUtils.Clone(_buffer),
                _iterations = _iterations,
                _block = _block,
                _blockSize = _blockSize,
                _startIndex = _startIndex,
                _endIndex = _endIndex
            };

        // initializes the state of the operation.
        private void Initialize()
        {
            ArrayUtils.ZeroFill(_buffer);
            _block = 1;
            _startIndex = 0;
            _endIndex = 0;
        }


        // iterative hash function
        private Span<byte> Func()
        {
            var intBlock = GetBigEndianBytes(_block);
            _hmacNotBuiltIn.Initialize();

            _hmacNotBuiltIn.TransformByteSpan(_salt);
            _hmacNotBuiltIn.TransformByteSpan(intBlock);

            Span<byte> temp = _hmacNotBuiltIn.TransformFinal().GetBytes();
            Span<byte> result = temp.ToArray();

            uint i = 2;
            while (i <= _iterations)
            {
                temp = _hmacNotBuiltIn.ComputeByteSpan(temp).GetBytes();
                var j = 0;
                while (j < _blockSize)
                {
                    result[j] = (byte)(result[j] ^ temp[j]);
                    j++;
                }

                i++;
            }

            _block++;
            return result;
        }

        /// <summary>
        /// Encodes an integer into a 4-byte array, in big endian.
        /// </summary>
        /// <param name="input">The integer to encode.</param>
        /// <returns>array of bytes, in big endian.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<byte> GetBigEndianBytes(uint input)
        {
            Span<byte> result = new byte[sizeof(uint)];
            Converters.ReadUInt32AsBytesBE(input, result);
            return result;
        }
    }
}