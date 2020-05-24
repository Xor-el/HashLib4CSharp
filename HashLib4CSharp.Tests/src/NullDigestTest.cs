using HashLib4CSharp.Base;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    [TestFixture]
    internal class NullDigestTest : NullDigestAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.NullDigestFactory.CreateNullDigest();
            HashOfEmptyData = "";
            HashOfDefaultData = "486173684C69623450617363616C";
            HashOfOneToNine = "313233343536373839";
            HashOfSmallLettersAToE = "6162636465";
        }
    }
}