using System;
using System.Security.Cryptography;
using HashLib4CSharp.Utils;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    internal abstract class AdapterTestBase : HashTestBase
    {
        protected static readonly Random Random;

        static AdapterTestBase()
        {
            Random = new Random();
        }

        protected static byte[] GenerateRandomByteArray(int count)
        {
            var randomBytes = new byte [count];
            Random.NextBytes(randomBytes);
            return randomBytes;
        }
    }

    internal abstract class HashAdapterTestBase : AdapterTestBase
    {
        protected HashAlgorithm HashAdapterInstance { get; set; }
        protected HashAlgorithm HashAlgorithmInstance { get; set; }

        [Test]
        public void TestHashingProducesSameResults()
        {
            var randomBytes = GenerateRandomByteArray(Random.Next(0, 255));
            AssertAreEqual(HashAlgorithmInstance.ComputeHash(randomBytes), HashAdapterInstance.ComputeHash(randomBytes),
                $"Computation mismatch when performing hash of '{Converters.ConvertBytesToHexString(randomBytes)}'");
        }

        [Test]
        public void TestIncrementalHashProducesSameResults()
        {
            var randomBytes = GenerateRandomByteArray(Random.Next(0, 255));

            HashAlgorithmInstance.TransformBlock(randomBytes, 0, randomBytes.Length, null, 0);
            HashAdapterInstance.TransformBlock(randomBytes, 0, randomBytes.Length, null, 0);

            AssertAreEqual(HashAlgorithmInstance.TransformFinalBlock(randomBytes, 0, randomBytes.Length),
                HashAdapterInstance.TransformFinalBlock(randomBytes, 0, randomBytes.Length),
                $"Computation mismatch when performing hash of '{Converters.ConvertBytesToHexString(randomBytes)}'");
        }

        [Test]
        public void TestHashSizeAreSame()
        {
            ExpectedString = HashAlgorithmInstance.HashSize.ToString();
            ActualString = HashAdapterInstance.HashSize.ToString();
            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class HMACAdapterTestBase : AdapterTestBase
    {
        protected HMAC HMACAdapterInstance { get; set; }
        protected HMAC HMACInstance { get; set; }

        [Test]
        public void TestHMACProducesSameResults()
        {
            var randomBytes = GenerateRandomByteArray(Random.Next(0, 255));
            AssertAreEqual(HMACInstance.ComputeHash(randomBytes), HMACAdapterInstance.ComputeHash(randomBytes),
                $"Computation mismatch when performing hmac of '{Converters.ConvertBytesToHexString(randomBytes)}'");
        }

        [Test]
        public void TestIncrementalHMACProducesSameResults()
        {
            var randomBytes = GenerateRandomByteArray(Random.Next(0, 255));

            HMACInstance.TransformBlock(randomBytes, 0, randomBytes.Length, null, 0);
            HMACAdapterInstance.TransformBlock(randomBytes, 0, randomBytes.Length, null, 0);

            AssertAreEqual(HMACInstance.TransformFinalBlock(randomBytes, 0, randomBytes.Length),
                HMACAdapterInstance.TransformFinalBlock(randomBytes, 0, randomBytes.Length),
                $"Computation mismatch when performing hmac of '{Converters.ConvertBytesToHexString(randomBytes)}'");
        }

        [Test]
        public void TestHMACChangeKeyAndInitializeProducesSameResults()
        {
            var randomBytes = GenerateRandomByteArray(Random.Next(0, 255));
            var key = GenerateRandomByteArray(Random.Next(0, 255));

            HMACInstance.Key = key;
            HMACAdapterInstance.Key = key;

            HMACInstance.Initialize();
            HMACAdapterInstance.Initialize();

            AssertAreEqual(HMACInstance.ComputeHash(randomBytes), HMACAdapterInstance.ComputeHash(randomBytes),
                $"Computation mismatch when performing hmac of '{Converters.ConvertBytesToHexString(randomBytes)}'");
        }

        [Test]
        public void TestHashSizeAreSame()
        {
            ExpectedString = HMACInstance.HashSize.ToString();
            ActualString = HMACAdapterInstance.HashSize.ToString();
            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestHMACKeyAreSame()
        {
            ExpectedString = HMACInstance.HashSize.ToString();
            ActualString = HMACAdapterInstance.HashSize.ToString();
            AssertAreEqual(HMACInstance.Key, HMACAdapterInstance.Key, "HMAC key mismatch");
        }
    }

    internal abstract class KDFAdapterTestBase : AdapterTestBase
    {
        protected DeriveBytes KDFAdapterInstance { get; set; }

        protected DeriveBytes KDFInstance { get; set; }

        protected int ByteCount { get; set; }

        [Test]
        public void TestKDFProducesSameResults()
        {
            AssertAreEqual(KDFInstance.GetBytes(ByteCount), KDFAdapterInstance.GetBytes(ByteCount),
                "Computation mismatch when performing kdf");
        }
    }
}