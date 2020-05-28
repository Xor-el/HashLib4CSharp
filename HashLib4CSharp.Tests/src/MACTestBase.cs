using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    internal abstract class MACTestBase : AlgorithmTestBase
    {
        protected IMACNotBuiltIn MacInstance { get; set; }
        protected IMACNotBuiltIn MacInstanceTwo { get; set; }

        [Test]
        public void ChangeKeyAndInitializeWorks()
        {
            ExpectedString = MacInstanceTwo.ComputeBytes(DefaultDataBytes).ToString();
            MacInstance.Key = OneToNineBytes;
            MacInstance.Initialize();
            MacInstance.TransformBytes(DefaultDataBytes);
            ActualString = MacInstance.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class HMACTestBase : MACTestBase
    {
    }

    internal abstract class KMACTestBase : MACTestBase
    {
        protected void DoComputeKMAC(IHash hashInstance, byte[] data)
        {
            hashInstance.Initialize();
            hashInstance.TransformBytes(data);
            var result = hashInstance.TransformFinal().GetBytes();

            ActualString = Converters.ConvertBytesToHexString(result);

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class Blake2MACTestBase : MACTestBase
    {
        protected static readonly byte[] ZeroToFifteenBytes = GenerateByteArrayInRange(0x00, 16);
        protected static readonly byte[] ZeroToThirtyOneBytes = GenerateByteArrayInRange(0x00, 32);

        protected void DoComputeBlake2(IHash hashInstance, byte[] data)
        {
            hashInstance.Initialize();
            hashInstance.TransformBytes(data);
            var result = hashInstance.TransformFinal().GetBytes();

            ActualString = Converters.ConvertBytesToHexString(result);

            AssertAreEqual(ExpectedString, ActualString);
        }
    }
}