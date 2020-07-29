using System;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    internal abstract class XOFTestBase : AlgorithmTestBase
    {
        protected IXOF XofInstance { get; set; }
        protected string XofOfEmptyData { get; set; }

        [Test]
        public void TestNullDestinationShouldThrowsCorrectException()
        {
            XofInstance.Initialize();
            XofInstance.TransformBytes(SmallLettersAToEBytes);
            Assert.Throws<ArgumentNullException>(() => XofInstance.DoOutput(NullBytes, 0, 0));
        }

        [Test]
        public void TestOutputOverflow()
        {
            XofInstance.Initialize();
            var output = new byte[(XofInstance.XofSizeInBits >> 3) + 1];
            XofInstance.TransformBytes(SmallLettersAToEBytes);
            Assert.Throws<ArgumentException>(() =>
                XofInstance.DoOutput(output, 0, output.Length));
        }

        [Test]
        public void TestOutputBufferTooShort()
        {
            XofInstance.Initialize();
            var output = new byte[XofInstance.XofSizeInBits >> 3];
            XofInstance.TransformBytes(SmallLettersAToEBytes);
            Assert.Throws<ArgumentException>(() =>
                XofInstance.DoOutput(output, 1, output.Length));
        }

        [Test]
        public void TestVeryLongXofOfEmptyData()
        {
            ExpectedString = XofOfEmptyData;
            ActualString = XofInstance.ComputeBytes(ZeroByteArray)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestVeryLongXofOfEmptyDataWithStreamingOutput()
        {
            const int xofStreamingChunkSize = 250;

            var tempResult = new byte[1000];
            var actualChunk = new byte[xofStreamingChunkSize];
            var expectedChunk = new byte[xofStreamingChunkSize];
            var xofOfEmptyDataBytes = Converters.ConvertHexStringToBytes(XofOfEmptyData);


            XofInstance.Initialize();
            XofInstance.TransformBytes(ZeroByteArray);

            // 1
            XofInstance.DoOutput(tempResult, 0, xofStreamingChunkSize);

            Array.Copy(tempResult, 0, actualChunk, 0, xofStreamingChunkSize);
            Array.Copy(xofOfEmptyDataBytes, 0, expectedChunk, 0, xofStreamingChunkSize);

            AssertAreEqual(expectedChunk, actualChunk, $"{XofInstance.Name} streaming test 1 mismatch");

            // 2
            XofInstance.DoOutput(tempResult, xofStreamingChunkSize, xofStreamingChunkSize);

            Array.Copy(tempResult, xofStreamingChunkSize, actualChunk, 0, xofStreamingChunkSize);
            Array.Copy(xofOfEmptyDataBytes, xofStreamingChunkSize, expectedChunk, 0, xofStreamingChunkSize);

            AssertAreEqual(expectedChunk, actualChunk, $"{XofInstance.Name} streaming test 2 mismatch");

            // 3
            XofInstance.DoOutput(tempResult, 500, xofStreamingChunkSize);

            Array.Copy(tempResult, 500, actualChunk, 0, xofStreamingChunkSize);
            Array.Copy(xofOfEmptyDataBytes, 500, expectedChunk, 0, xofStreamingChunkSize);

            AssertAreEqual(expectedChunk, actualChunk, $"{XofInstance.Name} streaming test 3 mismatch");

            // 4
            XofInstance.DoOutput(tempResult, 750, xofStreamingChunkSize);

            Array.Copy(tempResult, 750, actualChunk, 0, xofStreamingChunkSize);
            Array.Copy(xofOfEmptyDataBytes, 750, expectedChunk, 0, xofStreamingChunkSize);

            AssertAreEqual(expectedChunk, actualChunk, $"{XofInstance.Name} streaming test 4 mismatch");

            ActualString = Converters.ConvertBytesToHexString(tempResult);
            ExpectedString = XofOfEmptyData;

            AssertAreEqual(ExpectedString, ActualString);

            // Verify that Initialization Works
            XofInstance.Initialize();

            XofInstance.DoOutput(tempResult, 0, xofStreamingChunkSize);
            Array.Copy(tempResult, 0, actualChunk, 0, xofStreamingChunkSize);
            Array.Copy(xofOfEmptyDataBytes, 0, expectedChunk, 0, xofStreamingChunkSize);

            AssertAreEqual(expectedChunk, actualChunk, $"{XofInstance.Name} streaming initialization test fail");
        }

        [Test]
        public void TestXofShouldRaiseExceptionOnWriteAfterRead()
        {
            XofInstance.Initialize();
            var output = new byte[XofInstance.XofSizeInBits >> 3];
            XofInstance.TransformBytes(SmallLettersAToEBytes);
            XofInstance.DoOutput(output, 0, output.Length);
            // this call below should raise exception since we have already read from the Xof
            Assert.Throws<InvalidOperationException>(() => XofInstance.TransformBytes(SmallLettersAToEBytes));
        }

        [Test]
        public void TestXofCloningWorks()
        {
            XofInstance.Initialize();
            XofInstance.TransformBytes(ZeroToOneHundredAndNinetyNineBytes);
            var xofInstanceClone = (IXOF)XofInstance.Clone();

            var result = new byte[XofInstance.XofSizeInBits >> 3];
            var resultClone = new byte[xofInstanceClone.XofSizeInBits >> 3];

            XofInstance.DoOutput(result, 0, result.Length);
            xofInstanceClone.DoOutput(resultClone, 0, resultClone.Length);

            AssertAreEqual(result, resultClone, $"Error in '{XofInstance.Name}' cloning");
        }
    }

    internal abstract class ShakeTestBase : XOFTestBase
    {
    }

    internal abstract class CShakeTestBase : ShakeTestBase
    {
        protected static readonly byte[] EmailSignature =
            {0x45, 0x6D, 0x61, 0x69, 0x6C, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65};

        protected IXOF XofInstanceShake { get; set; }

        protected IXOF XofInstanceCShakeWithN { get; set; }
        protected string XofOfZeroToOneHundredAndNinetyNine { get; set; }

        [Test]
        public void TestCShakeAndShakeAreSameWhenNAndSAreEmpty()
        {
            ExpectedString = XofInstanceShake.ComputeBytes(ZeroByteArray)
                .ToString();
            ActualString = XofInstance.ComputeBytes(ZeroByteArray)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestCShakeWithN()
        {
            ExpectedString = XofOfZeroToOneHundredAndNinetyNine;
            ActualString = XofInstanceCShakeWithN.ComputeBytes(ZeroToOneHundredAndNinetyNineBytes)
                .ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public void TestCShakeWithNIncremental()
        {
            ExpectedString = XofOfZeroToOneHundredAndNinetyNine;
            XofInstanceCShakeWithN.Initialize();
            XofInstanceCShakeWithN.TransformBytes(ZeroToOneHundredAndNinetyNineBytes);
            ActualString = XofInstanceCShakeWithN.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class KMACXOFTestBase : XOFTestBase
    {
        protected void DoComputeKMACXOF(IXOF xofInstance, byte[] data)
        {
            var result = new byte[xofInstance.XofSizeInBits >> 3];

            xofInstance.Initialize();
            xofInstance.TransformBytes(data);
            xofInstance.DoOutput(result, 0, result.Length);

            ActualString = Converters.ConvertBytesToHexString(result);

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class Blake2XTestBase : XOFTestBase
    {
    }
}