using HashLib4CSharp.Base;
using HashLib4CSharp.Checksum;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    [TestFixture]
    internal class Adler32Test : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Checksum.CreateAdler32();
            HashOfEmptyData = "00000001";
            HashOfDefaultData = "25D40524";
            HashOfOneToNine = "091E01DE";
            HashOfSmallLettersAToE = "05C801F0";
        }
    }

    [TestFixture]
    internal class Crc32PKZipTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Checksum.CRC.CreateCrc32PKZip();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "D07C1A60";
            HashOfOneToNine = "CBF43926";
            HashOfSmallLettersAToE = "8587D865";
        }
    }

    [TestFixture]
    internal class Crc32CastagnoliTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Checksum.CRC.CreateCrc32Castagnoli();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "22B17746";
            HashOfOneToNine = "E3069283";
            HashOfSmallLettersAToE = "C450D697";
        }
    }

    [TestFixture]
    internal class CRCFactoryTest : CRCFactoryTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Checksum.CRC.CreateCRC(CRCModel.CRC32);
        }
    }
}