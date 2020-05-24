using HashLib4CSharp.Base;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    [TestFixture]
    internal class FNV64Test : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash64.CreateFNV64();
            HashOfEmptyData = "0000000000000000";
            HashOfDefaultData = "061A6856F5925B83";
            HashOfOneToNine = "B8FB573C21FE68F1";
            HashOfSmallLettersAToE = "77018B280326F529";
        }
    }

    [TestFixture]
    internal class FNV1a64Test : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash64.CreateFV1a64();
            HashOfEmptyData = "CBF29CE484222325";
            HashOfDefaultData = "5997E22BF92B0598";
            HashOfOneToNine = "06D5573923C6CDFC";
            HashOfSmallLettersAToE = "6348C52D762364A8";
        }
    }

    [TestFixture]
    internal class Murmur2_64Test : EightByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash64.CreateMurmur2_64();
            HashOfEmptyData = "0000000000000000";
            HashOfDefaultData = "831EFD69DC9E99F9";
            HashOfOneToNine = "4977490251674330";
            HashOfSmallLettersAToE = "1182974836D6DBB7";
            HashOfDefaultDataWithEightByteKey = "FF0A342F0AF9ADC6";
        }
    }

    internal class SipHash64_2_4Test : SixteenByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash64.CreateSipHash64_2_4();
            HashOfEmptyData = "310E0EDD47DB6F72";
            HashOfDefaultData = "4ED2198628C443AA";
            HashOfOneToNine = "FDFE0E0296FC60CA";
            HashOfSmallLettersAToE = "73B879EAE16345A7";
            HashOfDefaultDataWithSixteenByteKey = "4ED2198628C443AA";
        }
    }

    internal class XXHash64Test : EightByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash64.CreateXXHash64();
            HashOfEmptyData = "EF46DB3751D8E999";
            HashOfDefaultData = "0F1FADEDD0B77861";
            HashOfOneToNine = "8CB841DB40E6AE83";
            HashOfSmallLettersAToE = "07E3670C0C8DC7EB";
            HashOfDefaultDataWithEightByteKey = "68DCC1056096A94F";
        }
    }
}