using System;
using System.Text;
using HashLib4CSharp.Base;
using HashLib4CSharp.Utils;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    [TestFixture]
    internal class MD5HMACTest : HMACTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateMD5(), ZeroByteArray);
            MacInstance = HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateMD5(), ZeroByteArray);
            MacInstanceTwo = HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateMD5(), OneToNineBytes);

            HashOfEmptyData = "74E6F7298A9C2D168935F58C001BAD88";
            HashOfDefaultData = "E26A378B9A20DE63EE8C29402396553D";
            HashOfOneToNine = "56BEDC1F02772E32FDC71214BB795047";
            HashOfSmallLettersAToE = "B6DE7A4249C9E8338098CB8B18E14CA5";
        }

        [Test]
        public void TestSettingNullHashInstanceThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.HMAC.CreateHMAC(null, ZeroByteArray));

        [Test]
        public void TestSettingNullKeyThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.HMAC.CreateHMAC(HashFactory.Crypto.CreateMD5(), NullBytes));
    }

    [TestFixture]
    internal class KMAC128Test : KMACTestBase
    {
        private const int OutputSizeInBits = 32 * 8;

        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.KMAC.CreateKMAC128(ZeroByteArray, ZeroByteArray, 128);
            MacInstance = HashFactory.KMAC.CreateKMAC128(ZeroByteArray, ZeroByteArray, 128);
            MacInstanceTwo = HashFactory.KMAC.CreateKMAC128(OneToNineBytes, ZeroByteArray, 128);

            HashOfEmptyData = "E6AFF27FEF95903EB939BC3745730D34";
            HashOfDefaultData = "C40AE1DBC4E8411712D445D663E4073A";
            HashOfOneToNine = "EB3FE9620F82E24E33EAF4543A2B66EA";
            HashOfSmallLettersAToE = "C74861532E0154C2B71DC428079BABC3";
        }

        [Test]
        public void TestSettingNullKeyThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.KMAC.CreateKMAC128(NullBytes, ZeroByteArray, 128));

        [Test]
        public void TestSettingNullCustomizationThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.KMAC.CreateKMAC128(ZeroByteArray, NullBytes, 128));

        [Test]
        public void TestSettingInvalidSizeThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() =>
                HashFactory.KMAC.CreateKMAC128(ZeroByteArray, ZeroByteArray, 0));

        [Test]
        public void TestNISTSample1()
        {
            ExpectedString = "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E";
            var macInstance = HashFactory.KMAC.CreateKMAC128(ASCIICharacterBytes, ZeroByteArray,
                OutputSizeInBits);
            DoComputeKMAC(macInstance, ZeroToThreeBytes);
        }

        [Test]
        public void TestNISTSample2()
        {
            ExpectedString = "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5";
            var macInstance = HashFactory.KMAC.CreateKMAC128(ASCIICharacterBytes, CustomizationMessageBytes,
                OutputSizeInBits);
            DoComputeKMAC(macInstance, ZeroToThreeBytes);
        }

        [Test]
        public void TestNISTSample3()
        {
            ExpectedString = "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230";
            var macInstance = HashFactory.KMAC.CreateKMAC128(ASCIICharacterBytes, CustomizationMessageBytes,
                OutputSizeInBits);
            DoComputeKMAC(macInstance, ZeroToOneHundredAndNinetyNineBytes);
        }
    }

    [TestFixture]
    internal class KMAC256Test : KMACTestBase
    {
        private const int OutputSizeInBits = 64 * 8;

        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.KMAC.CreateKMAC256(ZeroByteArray, ZeroByteArray, 256);
            MacInstance = HashFactory.KMAC.CreateKMAC256(ZeroByteArray, ZeroByteArray, 256);
            MacInstanceTwo = HashFactory.KMAC.CreateKMAC256(OneToNineBytes, ZeroByteArray, 256);

            HashOfEmptyData = "0B002C51EC240A9AE0E9399CECB6A6A136452522342F7E6C17C62B8CD51F583B";
            HashOfDefaultData = "3669C34F6FC9F4EC516BE3B5ECF8CEC8F10C6AC58A327E43EA0C8F0C3B2BA324";
            HashOfOneToNine = "CBE22F258B331B8997CA00C67BB1CF2A3613EAE562198D6C8DA47F6AC99C44EC";
            HashOfSmallLettersAToE = "836FA1A76ED65801295522D8A6EF5A4D2C9FFD23BAAF867E06EA6236D8BFA3CE";
        }

        [Test]
        public void TestSettingNullKeyThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.KMAC.CreateKMAC256(NullBytes, ZeroByteArray, 256));

        [Test]
        public void TestSettingNullCustomizationThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.KMAC.CreateKMAC256(ZeroByteArray, NullBytes, 256));

        [Test]
        public void TestSettingInvalidSizeThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() =>
                HashFactory.KMAC.CreateKMAC256(ZeroByteArray, ZeroByteArray, 0));

        [Test]
        public void TestNISTSample1()
        {
            ExpectedString =
                "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD";
            var macInstance = HashFactory.KMAC.CreateKMAC256(ASCIICharacterBytes, CustomizationMessageBytes,
                OutputSizeInBits);
            DoComputeKMAC(macInstance, ZeroToThreeBytes);
        }

        [Test]
        public void TestNISTSample2()
        {
            ExpectedString =
                "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69";
            var macInstance = HashFactory.KMAC.CreateKMAC256(ASCIICharacterBytes, ZeroByteArray,
                OutputSizeInBits);
            DoComputeKMAC(macInstance, ZeroToOneHundredAndNinetyNineBytes);
        }

        [Test]
        public void TestNISTSample3()
        {
            ExpectedString =
                "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965";
            var macInstance = HashFactory.KMAC.CreateKMAC256(ASCIICharacterBytes, CustomizationMessageBytes,
                OutputSizeInBits);
            DoComputeKMAC(macInstance, ZeroToOneHundredAndNinetyNineBytes);
        }
    }

    [TestFixture]
    internal class Blake2BMACTest : Blake2MACTestBase
    {
        private const int OutputSizeInBits = 256;

        private byte[] PersonalizationBytes;

        [OneTimeSetUp]
        public void Setup()
        {
            PersonalizationBytes = Converters.ConvertStringToBytes("application", Encoding.UTF8);
            Array.Resize(ref PersonalizationBytes, 16);

            HashInstance =
                HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroByteArray, ZeroByteArray, ZeroByteArray, OutputSizeInBits);

            MacInstance = HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroByteArray, ZeroByteArray, ZeroByteArray, OutputSizeInBits);
            MacInstanceTwo =
                HashFactory.Blake2BMAC.CreateBlake2BMAC(OneToNineBytes, ZeroByteArray, ZeroByteArray, OutputSizeInBits);

            HashOfEmptyData = "0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A8";
            HashOfDefaultData = "DFDBC73BAF47DA4D9F645CC9AFFA76B95D78BF112C4EB3CC5372AD33B3DE004A";
            HashOfOneToNine = "16E0BF1F85594A11E75030981C0B670370B3AD83A43F49AE58A2FD6F6513CDE9";
            HashOfSmallLettersAToE = "CA96DD6B05B0BC353DD129077A871B7BBB3BD659C592C7E33DADAB30889943EE";
        }

        [Test]
        public void TestSettingNullKeyThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.Blake2BMAC.CreateBlake2BMAC(NullBytes, ZeroByteArray, ZeroByteArray, OutputSizeInBits));

        [Test]
        public void TestSettingNullSaltThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroByteArray, NullBytes, ZeroByteArray, OutputSizeInBits));

        [Test]
        public void TestSettingNullPersonalizationThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroByteArray, ZeroByteArray, NullBytes, OutputSizeInBits));

        [Test]
        public void TestSettingInvalidSizeThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() =>
                HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroByteArray, ZeroByteArray, ZeroByteArray, 0));

        [Test]
        public void TestSample1()
        {
            ExpectedString = "2A";
            var macInstance = HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroToThirtyOneBytes, ZeroByteArray, ZeroByteArray,
                1 * 8);
            DoComputeBlake2(macInstance,
                Converters.ConvertStringToBytes("Sample input for outlen<digest_length", Encoding.UTF8));
        }

        [Test]
        public void TestSample2()
        {
            ExpectedString = "51742FC491171EAF6B9459C8B93A44BBF8F44A0B4869A17FA178C8209918AD96";
            var macInstance = HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroToThirtyOneBytes, ZeroToFifteenBytes,
                PersonalizationBytes,
                32 * 8);
            DoComputeBlake2(macInstance,
                Converters.ConvertStringToBytes("Combo input with outlen, custom and salt", Encoding.UTF8));
        }

        [Test]
        public void TestSample3()
        {
            ExpectedString =
                "233A6C732212F4813EC4C9F357E35297E59A652FD24155205F00363F7C54734EE1E8C7329D92116CBEC62DB35EBB5D51F9E5C2BA41789B84AC9EBC266918E524";
            var macInstance = HashFactory.Blake2BMAC.CreateBlake2BMAC(ZeroToThirtyOneBytes, ZeroToFifteenBytes,
                PersonalizationBytes,
                64 * 8);
            DoComputeBlake2(macInstance,
                Converters.ConvertStringToBytes("Sample input for keylen<blocklen, salt and custom", Encoding.UTF8));
        }
    }

    [TestFixture]
    internal class Blake2SMACTest : Blake2MACTestBase
    {
        private const int OutputSizeInBits = 128;
        private static readonly byte[] ZeroToSevenBytes = GenerateByteArrayInRange(0x00, 8);

        private byte[] PersonalizationBytes;

        [OneTimeSetUp]
        public void Setup()
        {
            PersonalizationBytes = Converters.ConvertStringToBytes("app", Encoding.UTF8);
            Array.Resize(ref PersonalizationBytes, 8);

            HashInstance =
                HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroByteArray, ZeroByteArray, ZeroByteArray, OutputSizeInBits);

            MacInstance = HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroByteArray, ZeroByteArray, ZeroByteArray, OutputSizeInBits);
            MacInstanceTwo =
                HashFactory.Blake2SMAC.CreateBlake2SMAC(OneToNineBytes, ZeroByteArray, ZeroByteArray, OutputSizeInBits);

            HashOfEmptyData = "64550D6FFE2C0A01A14ABA1EADE0200C";
            HashOfDefaultData = "90ED1B7647A53ADDFA8C4B969471205D";
            HashOfOneToNine = "DCE1C41568C6AA166E2F8EAFCE34E617";
            HashOfSmallLettersAToE = "FFD7F0D7C62820AAF911CA23F8656D63";
        }

        [Test]
        public void TestSettingNullKeyThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.Blake2SMAC.CreateBlake2SMAC(NullBytes, ZeroByteArray, ZeroByteArray, OutputSizeInBits));

        [Test]
        public void TestSettingNullSaltThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroByteArray, NullBytes, ZeroByteArray, OutputSizeInBits));

        [Test]
        public void TestSettingNullPersonalizationThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroByteArray, ZeroByteArray, NullBytes, OutputSizeInBits));

        [Test]
        public void TestSettingInvalidSizeThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() =>
                HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroByteArray, ZeroByteArray, ZeroByteArray, 0));

        [Test]
        public void TestSample1()
        {
            ExpectedString = "07";
            var macInstance = HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroToThirtyOneBytes, ZeroByteArray, ZeroByteArray,
                1 * 8);
            DoComputeBlake2(macInstance,
                Converters.ConvertStringToBytes("Sample input for outlen<digest_length", Encoding.UTF8));
        }

        [Test]
        public void TestSample2()
        {
            ExpectedString = "6808D8DAAE537A16BF00E837010969A4";
            var macInstance = HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroToFifteenBytes, ZeroToSevenBytes,
                PersonalizationBytes,
                16 * 8);
            DoComputeBlake2(macInstance,
                Converters.ConvertStringToBytes("Combo input with outlen, custom and salt", Encoding.UTF8));
        }

        [Test]
        public void TestSample3()
        {
            ExpectedString =
                "E9F7704DFE5080A4AAFE62A806F53EA7F98FFC24175164158F18EC5497B961F5";
            var macInstance = HashFactory.Blake2SMAC.CreateBlake2SMAC(ZeroToFifteenBytes,
                Converters.ConvertHexStringToBytes("A205819E78D6D762"),
                PersonalizationBytes,
                32 * 8);
            DoComputeBlake2(macInstance,
                Converters.ConvertStringToBytes("Sample input for keylen<blocklen, salt and custom", Encoding.UTF8));
        }
    }
}