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
using System.Collections.Concurrent;
using System.Linq;
using System.Runtime.CompilerServices;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Checksum
{
    internal sealed class CRCFactory : Hash, ICRCFactory, ITransformBlock
    {
        private CRCModel _crcModel;
        private int _width;
        private ulong[] _crcTable;
        private int _mostSignificantShift;
        private bool _reflectIn;
        private bool _reflectOut;
        private ulong _xorOut;
        private ulong _hashValue;

        private static readonly ConcurrentDictionary<Tuple<int, ulong, bool>, ulong[]> ComputationTableCache =
            new ConcurrentDictionary<Tuple<int, ulong, bool>, ulong[]>();

        private static ulong ReflectBits(ulong value, int bitLength)
        {
            var reflectedValue = (ulong)0;

            for (var idx = 0; idx < bitLength; idx++)
            {
                reflectedValue <<= 1;

                reflectedValue |= value & 1;

                value >>= 1;
            }

            return reflectedValue;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong[] GetComputationTable(int width, ulong polynomial, bool reflectIn) =>
            ComputationTableCache.GetOrAdd(
                new Tuple<int, ulong, bool>(width, polynomial, reflectIn),
                tuple => GetComputationTableInternal(tuple));

        private static ulong[] GetComputationTableInternal(Tuple<int, ulong, bool> cacheKey)
        {
            var (width, polynomial, reflectIn) = cacheKey;

            var bitCount = 8;

            if (width < 8)
                bitCount = 1;


            var crcTable = new ulong[1 << bitCount];
            var mostSignificantBit = (ulong)1 << (width - 1);


            for (var idx = 0; idx < crcTable.Length; idx++)
            {
                var value = (ulong)idx;

                if (bitCount > 1 && reflectIn)
                    value = ReflectBits(value, bitCount);


                value <<= width - bitCount;


                for (var jdx = 0; jdx < bitCount; jdx++)
                {
                    value = (value & mostSignificantBit) > 0 ? (value << 1) ^ polynomial : value << 1;
                }

                if (reflectIn)
                    value = ReflectBits(value, width);

                value &= ulong.MaxValue >> (64 - width);

                crcTable[idx] = value;
            }

            return crcTable;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int CalculateHashSize(int width) => (width + 7) / 8;

        private static int ValidateModelAndCalculateHashSize(CRCModel crcModel)
        {
            if (crcModel == null) throw new ArgumentNullException(nameof(crcModel));

            if (crcModel.Width < 3 || crcModel.Width > 64)
                throw new ArgumentOutOfRangeException($"{nameof(crcModel)}.{nameof(crcModel.Width)}", crcModel.Width,
                    $"{nameof(crcModel)}.{nameof(crcModel.Width)} must be >= 3 and <= 64");

            return CalculateHashSize(crcModel.Width);
        }

        private CRCFactory(int hashSize, int blockSize) : base(hashSize, blockSize)
        {
        }

        public CRCFactory(CRCModel crcModel) : base(ValidateModelAndCalculateHashSize(crcModel), 1)
        {
            _crcModel = crcModel.Clone();

            _width = _crcModel.Width;
            _crcTable = GetComputationTable(_width, _crcModel.Polynomial, _crcModel.ReflectIn);

            _mostSignificantShift = _width < 8 ? _width - 1 : _width - 8;

            _reflectIn = _crcModel.ReflectIn;
            _reflectOut = _crcModel.ReflectOut;
            _xorOut = _crcModel.XorOut;
        }

        public override void Initialize()
        {
            _hashValue = _crcModel.InitialValue;

            if (_crcModel.ReflectIn)
                _hashValue = ReflectBits(_hashValue, _width);
        }

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var hashValue = _hashValue;

            var width = _width;
            var reflectIn = _reflectIn;
            var crcTable = _crcTable;
            var mostSignificantShift = _mostSignificantShift;
    
            var length = data.Length;

            for (var currentOffset = 0; currentOffset < length; currentOffset++)
            {
                if (width >= 8)
                {
                    // Process per byte
                    hashValue = reflectIn
                        ? (hashValue >> 8) ^ crcTable[(byte)hashValue ^ data[currentOffset]]
                        : (hashValue << 8) ^
                          crcTable[
                              (byte)(hashValue >> mostSignificantShift) ^ data[currentOffset]];
                }
                else
                {
                    // Process per bit
                    for (var currentBit = 0; currentBit < 8; currentBit++)
                    {
                        hashValue = reflectIn
                            ? (hashValue >> 1) ^
                              crcTable[
                                  (byte)(hashValue & 1) ^
                                  ((byte)(data[currentOffset] >> currentBit) & 1)]
                            : (hashValue << 1) ^
                              crcTable[
                                  (byte)((hashValue >> mostSignificantShift) & 1) ^
                                  ((byte)(data[currentOffset] >> (7 - currentBit)) & 1)];
                    }
                }
            }

            _hashValue = hashValue;
        }

        public override IHashResult TransformFinal()
        {
            if (_reflectIn ^ _reflectOut)
                _hashValue = ReflectBits(_hashValue, _width);

            _hashValue ^= _xorOut;
            _hashValue &= ulong.MaxValue >> (64 - _width);

            HashResult result;
            switch (CalculateHashSize(_width))
            {
                case 1:
                    result = new HashResult((byte)_hashValue);
                    break;
                case 2:
                    result = new HashResult((ushort)_hashValue);
                    break;
                case 3:
                case 4:
                    result = new HashResult((uint)_hashValue);
                    break;
                default:
                    result = new HashResult(_hashValue);
                    break;
            }

            Initialize();
            return result;
        }

        public override IHash Clone() =>
            new CRCFactory(HashSize, BlockSize)
            {
                _crcModel = _crcModel.Clone(),
                _width = _width,
                _mostSignificantShift = _mostSignificantShift,
                _reflectIn = _reflectIn,
                _reflectOut = _reflectOut,
                _xorOut = _xorOut,
                _hashValue = _hashValue,
                _crcTable = ArrayUtils.Clone(_crcTable),
                BufferSize = BufferSize
            };

        public override string Name => Names.FirstOrDefault();
        public CRCModel Model => _crcModel.Clone();
        public ulong CheckValue => _crcModel.CheckValue;
        public string[] Names => _crcModel.Names;
    }
}