using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Base;
using HashLib4CSharp.Checksum;
using HashLib4CSharp.Interfaces;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace HashLib4CSharp.Tests
{
    internal abstract class HashTestBase
    {
        protected static readonly int[] ChunkSizes = GenerateIntArrayInRange(1, 260);
        protected static byte[] NullBytes => null;

        protected static readonly byte[] ZeroByteArray = new byte[0];

        // "HashLib4Pascal"
        protected static readonly byte[] DefaultDataBytes =
            {0x48, 0x61, 0x73, 0x68, 0x4C, 0x69, 0x62, 0x34, 0x50, 0x61, 0x73, 0x63, 0x61, 0x6C};

        protected static readonly byte[] SmallLettersAToEBytes = GenerateByteArrayInRange(0x61, 5);

        protected static readonly byte[] OneToNineBytes = GenerateByteArrayInRange(0x31, 9);

        protected static readonly byte[] ZeroToThreeBytes = GenerateByteArrayInRange(0x0, 4);

        protected static readonly byte[] ZeroToOneHundredAndNinetyNineBytes = GenerateByteArrayInRange(0x0, 200);

        protected static readonly MemoryStream LargeMemoryStream =
            new MemoryStream(GenerateByteArrayInRange(0x00, 1024 * 1024));

        // "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_"
        protected static readonly byte[] ASCIICharacterBytes = GenerateByteArrayInRange(0x40, 32);

        // "My Tagged Application"
        protected static readonly byte[] CustomizationMessageBytes =
        {
            0x4D, 0x79, 0x20, 0x54, 0x61, 0x67, 0x67, 0x65, 0x64, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74,
            0x69, 0x6F, 0x6E
        };

        // "HashLib4Pascal012345678HashLib4Pascal012345678HashLib4Pascal012345678HashLib4Pascal012345678"
        protected static readonly byte[] ChunkedDataBytes =
        {
            0x48, 0x61, 0x73, 0x68, 0x4C, 0x69, 0x62, 0x34, 0x50, 0x61, 0x73, 0x63, 0x61, 0x6C, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x48, 0x61, 0x73, 0x68, 0x4C, 0x69, 0x62, 0x34, 0x50, 0x61, 0x73, 0x63, 0x61,
            0x6C, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x48, 0x61, 0x73, 0x68, 0x4C, 0x69, 0x62, 0x34,
            0x50, 0x61, 0x73, 0x63, 0x61, 0x6C, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x48, 0x61, 0x73,
            0x68, 0x4C, 0x69, 0x62, 0x34, 0x50, 0x61, 0x73, 0x63, 0x61, 0x6C, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x38
        };

        protected string ActualString { get; set; }
        protected string ExpectedString { get; set; }
        protected string HashOfEmptyData { get; set; }
        protected string HashOfDefaultData { get; set; }
        protected string HashOfOneToNine { get; set; }
        protected string HashOfSmallLettersAToE { get; set; }
        protected IHash HashInstance { get; set; }
        protected static IHash NullHashInstance => null;

        private static int[] GenerateIntArrayInRange(int start, int count) =>
            Enumerable.Range(start, count).ToArray();

        protected static byte[] GenerateByteArrayInRange(byte start, int count) =>
            Enumerable.Range(start, count).Select(i => (byte) i).ToArray();

        protected static byte[] GenerateRepeatingBytes(byte element, int count) =>
            Enumerable.Repeat(element, count).Select(i => i).ToArray();

        protected static bool AreEqual(byte[] a, byte[] b) => a.SequenceEqual(b);

        protected void AssertAreEqual<T>(T a, T b, string message = "") =>
            ClassicAssert.AreEqual(a, b,
                typeof(T) == typeof(string) ? $"expected '{ExpectedString}' but got '{ActualString}'." : message);

        protected void AssertAreNotEqual<T>(T a, T b, string message = "") =>
            ClassicAssert.AreNotEqual(a, b,
                typeof(T) == typeof(string)
                    ? $"'{ExpectedString}' and '{ActualString}' are not supposed to match."
                    : message);

        protected static T[] Clone<T>(T[] buffer) => (T[]) buffer.Clone();
    }

    internal abstract class CloneTestBase : HashTestBase
    {
        [Test]
        public void TestHashCloneIsCorrect()
        {
            var count = DefaultDataBytes.Length - 3;
            var chunk1 = new byte[count];
            Array.Copy(DefaultDataBytes, 0, chunk1, 0, chunk1.Length);

            var chunk2 = new byte[DefaultDataBytes.Length - count];
            Array.Copy(DefaultDataBytes, count, chunk1, 0, chunk2.Length);

            HashInstance.Initialize();
            HashInstance.TransformBytes(chunk1);
            // Make Clone Of Current State
            var hashInstanceClone = HashInstance.Clone();

            HashInstance.TransformBytes(chunk2);
            ExpectedString = HashInstance.TransformFinal().ToString();

            hashInstanceClone.TransformBytes(chunk2);
            ActualString = hashInstanceClone.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHashCloneMatchesMainHash()
        {
            HashInstance.Initialize();

            foreach (var b in DefaultDataBytes)
            {
                HashInstance.TransformBytes(new[] {b});
            }

            var hashInstanceClone = HashInstance.Clone();

            ExpectedString = HashInstance.TransformFinal().ToString();
            ActualString = hashInstanceClone.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHashCloneIsUnique()
        {
            HashInstance.Initialize();
            HashInstance.BufferSize = 64 * 1024; // 64Kb
            ExpectedString = HashInstance.BufferSize.ToString();
            // Make Clone Of Current State
            var hashInstanceClone = HashInstance.Clone();
            hashInstanceClone.BufferSize = 128 * 1024; // 128Kb
            ActualString = hashInstanceClone.BufferSize.ToString();
            AssertAreNotEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class CommonTestBase : CloneTestBase
    {
        [Test]
        public void TestHashingNullDataThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() => HashInstance.ComputeBytes(NullBytes));

        [Test]
        public void TestHashingNullDataIncrementalThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
            {
                HashInstance.Initialize();
                HashInstance.TransformBytes(NullBytes, 0, 0);
                HashInstance.TransformFinal();
            });

        [Test]
        public void TestHashingZeroByteReadOnlySpanVsZeroByteArray() => AssertAreEqual(
            HashInstance.ComputeByteSpan(ZeroByteArray).ToString(),
            HashInstance.ComputeBytes(ZeroByteArray).ToString());

        [Test]
        public void TestHashingReadOnlySpanVsArray() =>
            AssertAreEqual(HashInstance.ComputeByteSpan(new ReadOnlySpan<byte>(DefaultDataBytes)).ToString(),
                HashInstance.ComputeBytes(DefaultDataBytes).ToString());

        private static void Computation(ref byte[] result, IHash hash, int iterations)
        {
            for (var i = 0; i < iterations; i++)
            {
                result = hash.ComputeBytes(result).GetBytes();
            }
        }

        [Test]
        public void TestIndexChunkedDataIncrementalHash()
        {
            var hashInstanceClone = HashInstance.Clone();

            for (var idx = 0; idx < ChunkedDataBytes.Length; idx++)
            {
                var count = ChunkedDataBytes.Length - idx;

                var temp = new byte[count];
                Array.Copy(ChunkedDataBytes, idx, temp, 0, count);

                HashInstance.Initialize();
                HashInstance.TransformBytes(ChunkedDataBytes, idx, count);

                ExpectedString = hashInstanceClone.ComputeBytes(temp).ToString();
                ActualString = HashInstance.TransformFinal().ToString();
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public void TestAnotherChunkedDataIncrementalHash()
        {
            var hashInstanceClone = HashInstance.Clone();
            for (var idx = 0; idx < ChunkSizes.Length / sizeof(int); idx++)
            {
                var size = ChunkSizes[idx];
                HashInstance.Initialize();
                var jdx = size;
                byte[] temp;
                while (jdx < ChunkedDataBytes.Length)
                {
                    temp = new byte[size];
                    Array.Copy(ChunkedDataBytes, jdx - size, temp, 0, temp.Length);
                    HashInstance.TransformBytes(temp);

                    jdx += size;
                }

                temp = new byte[ChunkedDataBytes.Length - (jdx - size)];
                Array.Copy(ChunkedDataBytes, jdx - size, temp, 0, temp.Length);

                HashInstance.TransformBytes(temp);

                ExpectedString = hashInstanceClone.ComputeBytes(ChunkedDataBytes).ToString();
               ActualString = HashInstance.TransformFinal().ToString();
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public unsafe void TestUntypedInterface()
        {
            fixed (byte* srcPtr = SmallLettersAToEBytes)
            {
                ExpectedString = HashInstance.ComputeBytes(SmallLettersAToEBytes).ToString();
                ActualString = HashInstance.ComputeUntyped(srcPtr, SmallLettersAToEBytes.Length)
                    .ToString();
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public void TestInitializeWorks()
        {
            HashInstance.Initialize();
            HashInstance.TransformBytes(DefaultDataBytes);
            ExpectedString = HashInstance.TransformFinal().ToString();

            HashInstance.Initialize();
            HashInstance.TransformBytes(DefaultDataBytes);
            ActualString = HashInstance.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestMultiThreadingAndCloneWorks()
        {
            const int iterations = 20;

            var h1 = HashInstance.Clone();
            var h2 = HashInstance.Clone();
            var h3 = HashInstance.Clone();
            var h4 = HashInstance.Clone();

            var a = Clone(DefaultDataBytes);
            var b = Clone(DefaultDataBytes);
            var c = Clone(DefaultDataBytes);
            var d = Clone(DefaultDataBytes);

            var t1 = Task.Factory.StartNew(() => Computation(ref a, h1, iterations));
            var t2 = Task.Factory.StartNew(() => Computation(ref b, h2, iterations));
            var t3 = Task.Factory.StartNew(() => Computation(ref c, h3, iterations));
            var t4 = Task.Factory.StartNew(() => Computation(ref d, h4, iterations));

            Task.WaitAll(t1, t2, t3, t4);

            ClassicAssert.IsTrue(AreEqual(a, b) == AreEqual(c, d),
                $"MultiThreading and Clone test failed for '{HashInstance.Name}'");
        }

        [Test]
        public void TestStreamAndArrayHashMatchOne()
        {
            LargeMemoryStream.Position = 0;
            ActualString = HashInstance.ComputeStream(LargeMemoryStream).ToString();
            ExpectedString = HashInstance.ComputeBytes(LargeMemoryStream.ToArray()).ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestStreamAndArrayHashMatchTwo()
        {
            LargeMemoryStream.Position = 0;
            ActualString = HashInstance.ComputeStream(LargeMemoryStream, LargeMemoryStream.Length / 2).ToString();
            HashInstance.Initialize();
            HashInstance.TransformBytes(LargeMemoryStream.ToArray(), 0, (int) (LargeMemoryStream.Length / 2));
            ExpectedString = HashInstance.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestCancellationTokenWorks()
        {
            LargeMemoryStream.Position = 0;
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();
            Assert.CatchAsync<OperationCanceledException>(() =>
                HashInstance.ComputeStreamAsync(LargeMemoryStream, -1, cancellationTokenSource.Token));
        }
    }

    internal abstract class CRCFactoryTestBase : CommonTestBase
    {
        [Test]
        public void TestCheckValue()
        {
            foreach (var propertyInfo in typeof(CRCModel).GetProperties(BindingFlags.Public | BindingFlags.Static))
            {
                var crcModel = (CRCModel) propertyInfo.GetValue(null);
                var crcInstance = HashFactory.Checksum.CRC.CreateCRC(crcModel);
                ExpectedString = $"{((ICRCFactory) crcInstance).CheckValue:X16}";
                ActualString = crcInstance.ComputeBytes(OneToNineBytes).ToString().PadLeft(16, '0');
                ClassicAssert.AreEqual(ExpectedString, ActualString,
                    $"{crcInstance.Name}: expected {ExpectedString} but got {ActualString}");
            }
        }
    }

    internal abstract class AlgorithmTestBase : CommonTestBase
    {
        [Test]
        public void TestHashOfEmptyData()
        {
            ExpectedString = HashOfEmptyData;
            ActualString = HashInstance.ComputeBytes(ZeroByteArray).ToString();
            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHashOfDefaultData()
        {
            ExpectedString = HashOfDefaultData;
            ActualString = HashInstance.ComputeBytes(DefaultDataBytes).ToString();
            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHashOfSmallLettersAToE()
        {
            ExpectedString = HashOfSmallLettersAToE;
            ActualString = HashInstance.ComputeBytes(SmallLettersAToEBytes).ToString();
            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHashOfOneToNine()
        {
            ExpectedString = HashOfOneToNine;
            ActualString = HashInstance.ComputeBytes(OneToNineBytes).ToString();
            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHashOfEmptyStream()
        {
            using (var stream = new MemoryStream(ZeroByteArray))
            {
                ExpectedString = HashOfEmptyData;
                ActualString = HashInstance.ComputeStream(stream).ToString();
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public void TestHashOfDefaultDataStream()
        {
            using (var stream = new MemoryStream(DefaultDataBytes))
            {
                ExpectedString = HashOfDefaultData;
                ActualString = HashInstance.ComputeStream(stream).ToString();
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public async Task TestHashOfEmptyStreamAsync()
        {
            using (var stream = new MemoryStream(ZeroByteArray))
            {
                ExpectedString = HashOfEmptyData;
                var hashResult = await HashInstance.ComputeStreamAsync(stream);
                ActualString = hashResult.ToString();
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public async Task TestHashOfDefaultDataStreamAsync()
        {
            using (var stream = new MemoryStream(DefaultDataBytes))
            {
                ExpectedString = HashOfDefaultData;
                var hashResult = await HashInstance.ComputeStreamAsync(stream);
                ActualString = hashResult.ToString();
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public void TestIncrementalHash()
        {
            ExpectedString = HashOfDefaultData;
            HashInstance.Initialize();
            foreach (var b in DefaultDataBytes)
            {
                HashInstance.TransformBytes(new[] {b});
            }

            ActualString = HashInstance.TransformFinal().ToString();
            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class NullDigestAlgorithmTestBase : AlgorithmTestBase
    {
        [Test]
        public void TestQueryingHashSizeThrowsCorrectException() =>
            Assert.Throws<NotImplementedException>(() => { _ = HashInstance.HashSize; });

        [Test]
        public void TestQueryingBlockSizeThrowsCorrectException() =>
            Assert.Throws<NotImplementedException>(() => { _ = HashInstance.BlockSize; });
    }

    internal abstract class ByteKeyAlgorithmTestBase : AlgorithmTestBase
    {
        [Test]
        public void TestSettingEmptyKeyDoesNotThrow() =>
            Assert.DoesNotThrow(() => ((IHashWithKey) HashInstance).Key = ZeroByteArray);

        [Test]
        public void TestEmptyKeyShouldBeSameAsDefaultKey()
        {
            ExpectedString = HashOfDefaultData;
            var hashWithKey = (IHashWithKey) HashInstance;
            hashWithKey.Key = ZeroByteArray;
            ActualString = hashWithKey.ComputeBytes(DefaultDataBytes)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestSettingNullKeyThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() => ((IHashWithKey) HashInstance).Key = NullBytes);

        [Test]
        public void TestSettingKeyWithLengthLessThanDefinedSizeThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() =>
            {
                var hashWithKey = (IHashWithKey) HashInstance;
                hashWithKey.Key = GenerateByteArrayInRange(0x0, hashWithKey.KeyLength - 1);
            });

        [Test]
        public void TestSettingKeyWithLengthGreaterThanDefinedSizeThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() =>
            {
                var hashWithKey = (IHashWithKey) HashInstance;
                hashWithKey.Key = GenerateByteArrayInRange(0x0, ((IHashWithKey) HashInstance).KeyLength + 1);
            });

        [Test]
        public void TestKeySetterAndGetterWorks()
        {
            var hashWithKey = (IHashWithKey) HashInstance;
            var key = GenerateByteArrayInRange(0x0, hashWithKey.KeyLength);
            hashWithKey.Key = key;

            AssertAreEqual(key, hashWithKey.Key, $"Key mismatch in '{hashWithKey.Name}'");
        }
    }

    internal abstract class FourByteKeyAlgorithmTestBase : ByteKeyAlgorithmTestBase
    {
        //  {0xFF, 0xFF, 0xFF, 0xFF};
        private static readonly byte[] MaxUInt32Bytes = GenerateRepeatingBytes(0xFF, sizeof(uint));

        protected string HashOfDefaultDataWithFourByteKey { get; set; }

        [Test]
        public void TestWithMaxUInt32AsKey()
        {
            ExpectedString = HashOfDefaultDataWithFourByteKey;
            var hashWithKey = (IHashWithKey) HashInstance;
            hashWithKey.Key = MaxUInt32Bytes;
            ActualString = hashWithKey.ComputeBytes(DefaultDataBytes)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class EightByteKeyAlgorithmTestBase : ByteKeyAlgorithmTestBase
    {
        // {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        private static readonly byte[] MaxUInt64Bytes = GenerateRepeatingBytes(0xFF, sizeof(ulong));

        protected string HashOfDefaultDataWithEightByteKey { get; set; }

        [Test]
        public void TestWithMaxUInt64AsKey()
        {
            ExpectedString = HashOfDefaultDataWithEightByteKey;
            var hashWithKey = (IHashWithKey) HashInstance;
            hashWithKey.Key = MaxUInt64Bytes;
            ActualString = hashWithKey.ComputeBytes(DefaultDataBytes)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class SixteenByteKeyAlgorithmTestBase : ByteKeyAlgorithmTestBase
    {
        // {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        private static readonly byte[] ZeroToFifteenBytes = GenerateByteArrayInRange(0x0, 16);

        protected string HashOfDefaultDataWithSixteenByteKey { get; set; }

        [Test]
        public void TestWithZeroToFifteenAsKey()
        {
            ExpectedString = HashOfDefaultDataWithSixteenByteKey;
            var hashWithKey = (IHashWithKey) HashInstance;
            hashWithKey.Key = ZeroToFifteenBytes;
            ActualString = hashWithKey.ComputeBytes(DefaultDataBytes)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class CryptoAlgorithmTestBase : AlgorithmTestBase
    {
        // "Hash"
        private static readonly byte[] HMACShortKeyBytes =
            {0x48, 0x61, 0x73, 0x68};

        // {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13};
        private static readonly byte[] ZeroToNineteenBytes = GenerateByteArrayInRange(0x0, 20);

        // "This is a very long key used to test HMAC functionality when key length is greater than the hash blocksize"
        private static readonly byte[] HMACLongKeyBytes =
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x76, 0x65, 0x72, 0x79, 0x20, 0x6C, 0x6F, 0x6E,
            0x67, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x48, 0x4D, 0x41, 0x43, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x69, 0x74,
            0x79, 0x20, 0x77, 0x68, 0x65, 0x6E, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x6C, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x20,
            0x69, 0x73, 0x20, 0x67, 0x72, 0x65, 0x61, 0x74, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x68, 0x61, 0x73, 0x68, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x73, 0x69, 0x7A, 0x65
        };

        protected string HashOfDefaultDataHMACWithShortKey { get; set; }
        protected string HashOfDefaultDataHMACWithLongKey { get; set; }
        protected IHMACNotBuiltIn HMACInstance { get; set; }

        [Test]
        public void TestSettingNullHashInstanceInHMACThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.HMAC.CreateHMAC(NullHashInstance, ZeroByteArray));

        [Test]
        public void TestSettingNullKeyInHMACThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() => HMACInstance.Key = NullBytes);

        [Test]
        public void TestHMACOfNullDataThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() => HMACInstance.ComputeBytes(NullBytes));

        [Test]
        public void TestHMACWithDefaultDataShortKey()
        {
            ExpectedString = HashOfDefaultDataHMACWithShortKey;
            HMACInstance.Key = HMACShortKeyBytes;
            ActualString = HMACInstance.ComputeBytes(DefaultDataBytes)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHMACWithDefaultDataLongKey()
        {
            ExpectedString = HashOfDefaultDataHMACWithLongKey;
            HMACInstance.Key = HMACLongKeyBytes;
            ActualString = HMACInstance.ComputeBytes(DefaultDataBytes)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHMACCloneWithShortKeyIsCorrect()
        {
            var count = DefaultDataBytes.Length - 3;
            var chunk1 = new byte[count];
            Array.Copy(DefaultDataBytes, 0, chunk1, 0, chunk1.Length);

            var chunk2 = new byte[DefaultDataBytes.Length - count];
            Array.Copy(DefaultDataBytes, count, chunk1, 0, chunk2.Length);


            HMACInstance.Key = HMACShortKeyBytes;
            HMACInstance.Initialize();
            HMACInstance.TransformBytes(chunk1);
            // Make Clone Of Current State
            var hmacInstanceClone = HMACInstance.Clone();

            HMACInstance.TransformBytes(chunk2);
            ExpectedString = HMACInstance.TransformFinal().ToString();

            hmacInstanceClone.TransformBytes(chunk2);
            ActualString = hmacInstanceClone.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHMACCloneWithLongKeyIsCorrect()
        {
            var count = DefaultDataBytes.Length - 3;
            var chunk1 = new byte[count];
            Array.Copy(DefaultDataBytes, 0, chunk1, 0, chunk1.Length);

            var chunk2 = new byte[DefaultDataBytes.Length - count];
            Array.Copy(DefaultDataBytes, count, chunk1, 0, chunk2.Length);


            HMACInstance.Key = HMACLongKeyBytes;
            HMACInstance.Initialize();
            HMACInstance.TransformBytes(chunk1);
            // Make Clone Of Current State
            var hmacInstanceClone = HMACInstance.Clone();

            HMACInstance.TransformBytes(chunk2);
            ExpectedString = HMACInstance.TransformFinal().ToString();

            hmacInstanceClone.TransformBytes(chunk2);
            ActualString = hmacInstanceClone.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHMACKeySetterAndGetterWorks()
        {
            HMACInstance.Key = ZeroToNineteenBytes;

            AssertAreEqual(ZeroToNineteenBytes, HMACInstance.Key, $"Key mismatch in '{HMACInstance.Name}'");
        }

        [Test]
        public void TestHMACWorkingKeyIsCorrectShortKey()
        {
            var key = GenerateByteArrayInRange(0x0, HMACInstance.BlockSize - 1);
            HMACInstance.Key = key;
            AssertAreEqual(key, HMACInstance.Key,
                $"Working key mismatch in '{HMACInstance.Name}'");
        }

        [Test]
        public void TestHMACWorkingKeyIsCorrectLongKey()
        {
            var key = GenerateByteArrayInRange(0x0, HMACInstance.BlockSize + 1);

            HMACInstance.Key = key;
            AssertAreEqual(HashInstance.ComputeBytes(key).GetBytes(), HMACInstance.WorkingKey,
                $"Working key mismatch in '{HMACInstance.Name}'");
        }

        [Test]
        public void TestSplits()
        {
            var input = ZeroToNineteenBytes;

            for (var i = 0; i < input.Length; i++)
            {
                HashInstance.Initialize();
                HashInstance.TransformBytes(input, 0, i);
                ExpectedString = HashInstance.TransformFinal().ToString();

                for (var j = 0; j <= i; j++)
                {
                    for (var k = j; k <= i; k++)
                    {
                        HashInstance.Initialize();
                        HashInstance.TransformBytes(input, 0, j);
                        HashInstance.TransformBytes(input, j, k - j);
                        HashInstance.TransformBytes(input, k, i - k);
                        ActualString = HashInstance.TransformFinal().ToString();

                        AssertAreEqual(ExpectedString, ActualString);
                    }
                }
            }
        }
    }

    internal abstract class Blake2CryptoAlgorithmTestBase : CryptoAlgorithmTestBase
    {
        protected IHash HashInstanceWithKey { get; set; }
        protected string[] KeyedTestVectors { get; set; }
        protected string[] UnKeyedTestVectors { get; set; }

        protected readonly byte[] ZeroToThirtyOneBytes = GenerateByteArrayInRange(0x00, 32);

        protected readonly byte[] ZeroToSixtyThreeBytes = GenerateByteArrayInRange(0x00, 64);

        [Test]
        public void TestCheckKeyedTestVectors()
        {
            for (var idx = 0; idx < KeyedTestVectors.Length; idx++)
            {
                ActualString = HashInstanceWithKey.ComputeBytes(GenerateByteArrayInRange(0, idx)).ToString();
                ExpectedString = KeyedTestVectors[idx];
                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public void TestCheckUnKeyedTestVectors()
        {
            for (var idx = 0; idx < UnKeyedTestVectors.Length; idx++)
            {
                ActualString = HashInstance.ComputeBytes(GenerateByteArrayInRange(0, idx)).ToString();
                ExpectedString = UnKeyedTestVectors[idx];
                AssertAreEqual(ExpectedString, ActualString);
            }
        }
    }
}