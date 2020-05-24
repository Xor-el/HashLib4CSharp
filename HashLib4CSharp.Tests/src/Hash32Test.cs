using HashLib4CSharp.Base;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    [TestFixture]
    internal class APTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateAP();
            HashOfEmptyData = "AAAAAAAA";
            HashOfDefaultData = "7F14EFED";
            HashOfOneToNine = "C0E86BE5";
            HashOfSmallLettersAToE = "7F6A697A";
        }
    }

    internal class BernsteinTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateBernstein();
            HashOfEmptyData = "00001505";
            HashOfDefaultData = "C4635F48";
            HashOfOneToNine = "35CDBB82";
            HashOfSmallLettersAToE = "0F11B894";
        }
    }

    internal class Bernstein1Test : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateBernstein1();
            HashOfEmptyData = "00001505";
            HashOfDefaultData = "2D122E48";
            HashOfOneToNine = "3BABEA14";
            HashOfSmallLettersAToE = "0A1DEB04";
        }
    }

    internal class BKDRTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateBKDR();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "29E11B15";
            HashOfOneToNine = "DE43D6D5";
            HashOfSmallLettersAToE = "B3EDEA13";
        }
    }

    internal class DEKTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateDEK();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "8E01E947";
            HashOfOneToNine = "AB4ACBA5";
            HashOfSmallLettersAToE = "0C2080E5";
        }
    }

    internal class DJBTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateDJB();
            HashOfEmptyData = "00001505";
            HashOfDefaultData = "C4635F48";
            HashOfOneToNine = "35CDBB82";
            HashOfSmallLettersAToE = "0F11B894";
        }
    }

    internal class ELFTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateELF();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "01F5B2CC";
            HashOfOneToNine = "0678AEE9";
            HashOfSmallLettersAToE = "006789A5";
        }
    }

    internal class FNVTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateFNV();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "BE611EA3";
            HashOfOneToNine = "D8D70BF1";
            HashOfSmallLettersAToE = "B2B39969";
        }
    }

    internal class FNV1aTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateFNV1a();
            HashOfEmptyData = "811C9DC5";
            HashOfDefaultData = "1892F1F8";
            HashOfOneToNine = "BB86B11C";
            HashOfSmallLettersAToE = "749BCF08";
        }
    }

    internal class Jenkins3Test : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateJenkins3();
            HashOfEmptyData = "DEADBEEF";
            HashOfDefaultData = "F0F69CEF";
            HashOfOneToNine = "845D9A96";
            HashOfSmallLettersAToE = "026D72DE";
        }
    }

    internal class JSTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateJS();
            HashOfEmptyData = "4E67C6A7";
            HashOfDefaultData = "683AFCFE";
            HashOfOneToNine = "90A4224B";
            HashOfSmallLettersAToE = "62E8C8B5";
        }
    }

    internal class Murmur2Test : FourByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateMurmur2();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "30512DE6";
            HashOfOneToNine = "DCCB0167";
            HashOfSmallLettersAToE = "5F09A8DE";
            HashOfDefaultDataWithFourByteKey = "B15D52F0";
        }
    }

    internal class MurmurHash3_x86_32Test : FourByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateMurmurHash3_x86_32();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "3D97B9EB";
            HashOfOneToNine = "B4FEF382";
            HashOfSmallLettersAToE = "E89B9AF6";
            HashOfDefaultDataWithFourByteKey = "B05606FE";
        }
    }

    internal class OneAtTimeTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateOneAtTime();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "4E379A4F";
            HashOfOneToNine = "C66B58C5";
            HashOfSmallLettersAToE = "B98559FC";
        }
    }

    internal class PJWTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreatePJW();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "01F5B2CC";
            HashOfOneToNine = "0678AEE9";
            HashOfSmallLettersAToE = "006789A5";
        }
    }

    internal class RotatingTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateRotating();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "158009D3";
            HashOfOneToNine = "1076548B";
            HashOfSmallLettersAToE = "00674525";
        }
    }

    internal class RSTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateRS();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "9EF98E63";
            HashOfOneToNine = "704952E9";
            HashOfSmallLettersAToE = "A4A13F5D";
        }
    }

    internal class SDBMTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateSDBM();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "3001A5C9";
            HashOfOneToNine = "68A07035";
            HashOfSmallLettersAToE = "BD500063";
        }
    }

    internal class ShiftAndXorTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateShiftAndXor();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "BD0A7DA4";
            HashOfOneToNine = "E164F745";
            HashOfSmallLettersAToE = "0731B823";
        }
    }

    internal class SuperFastTest : AlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateSuperFast();
            HashOfEmptyData = "00000000";
            HashOfDefaultData = "F00EB3C0";
            HashOfOneToNine = "9575A2E9";
            HashOfSmallLettersAToE = "51ED072E";
        }
    }

    internal class XXHash32Test : FourByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash32.CreateXXHash32();
            HashOfEmptyData = "02CC5D05";
            HashOfDefaultData = "6A1C7A99";
            HashOfOneToNine = "937BAD67";
            HashOfSmallLettersAToE = "9738F19B";
            HashOfDefaultDataWithFourByteKey = "728C6772";
        }
    }
}