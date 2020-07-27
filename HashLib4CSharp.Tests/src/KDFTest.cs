using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HashLib4CSharp.Base;
using HashLib4CSharp.Enum;
using HashLib4CSharp.KDF;
using HashLib4CSharp.Utils;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    [TestFixture]
    internal class PBKDF2HMACSHA1Test : PBKDF2HMACTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            ExpectedString = "BFDE6BE94DF7E11DD409BCE20A0255EC327CB936FFE93643";
            Password = new byte[] {0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64};
            Salt = new byte[] {0x78, 0x57, 0x8E, 0x5A, 0x5D, 0x63, 0xCB, 0x06};
            ByteCount = 24;
            KdfInstance =
                HashFactory.KDF.PBKDF2HMAC.CreatePBKDF2HMAC(HashFactory.Crypto.CreateSHA1(), Password, Salt, 2048);
        }
    }

    internal class PBKDF2HMACSHA256Test : PBKDF2HMACTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            ExpectedString = "0394A2EDE332C9A13EB82E9B24631604C31DF978B4E2F0FBD2C549944F9D79A5";
            Password = new byte[] {0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64};
            Salt = new byte[] {0x73, 0x61, 0x6C, 0x74};
            ByteCount = 32;
            KdfInstance =
                HashFactory.KDF.PBKDF2HMAC.CreatePBKDF2HMAC(HashFactory.Crypto.CreateSHA2_256(), Password, Salt,
                    100000);
        }
    }

    [TestFixture]
    internal class PBKDFScryptTest : PBKDFScryptTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            ByteCount = 32;
            KdfInstance =
                HashFactory.KDF.PBKDFScrypt.CreatePBKDFScrypt(ZeroByteArray, ZeroByteArray, 16, 1, 1);
        }

        [Test]
        public void TestNullPasswordThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDFScrypt.CreatePBKDFScrypt(NullBytes,
                    ZeroByteArray, 16, 1, 1));

        [Test]
        public void TestNullSaltThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDFScrypt.CreatePBKDFScrypt(
                    ZeroByteArray, NullBytes, 16, 1, 1));

        [Test]
        public void TestOkParameters1() => DoCheckOk("Minimal values", ZeroByteArray, ZeroByteArray, 2, 1, 1, 1);

        [Test]
        public void TestOkParameters2() =>
            DoCheckOk("Cost parameter 32768 OK for r = 1", ZeroByteArray, ZeroByteArray, 32768, 1, 1, 1);

        [Test, Ignore("This test takes a very long time")]
        public void TestOkParameters3() =>
            DoCheckOk("Parallelisation parameter 65535 OK for r = 4", ZeroByteArray, ZeroByteArray, 2, 32,
                65535, 1);

        [Test]
        public void TestIllegalParameters1() =>
            DoCheckIllegal("Cost parameter must be > 1", ZeroByteArray, ZeroByteArray, 1, 1, 1, 1);

        [Test]
        public void TestIllegalParameters2() =>
            DoCheckIllegal("Cost parameter must < 65536 for r = 1", ZeroByteArray, ZeroByteArray,
                65536, 1, 1, 1);

        [Test]
        public void TestIllegalParameters3() =>
            DoCheckIllegal("Block size must be >= 1", ZeroByteArray, ZeroByteArray, 2, 0, 2, 1);

        [Test]
        public void TestIllegalParameters4() =>
            DoCheckIllegal("Parallelisation parameter must be >= 1", ZeroByteArray, ZeroByteArray, 2,
                1, 0, 1);

        [Test]
        public void TestIllegalParameters5() =>
            DoCheckIllegal("Parallelisation parameter must be < 65535 for r = 4", ZeroByteArray,
                ZeroByteArray, 2, 32, 65536, 1);

        [Test]
        public void TestIllegalParameters6() =>
            DoCheckIllegal("outputSize parameter must be > 1", ZeroByteArray, ZeroByteArray, 2, 1, 1, 0);

        [Test]
        public void TestVector1()
        {
            ExpectedString =
                "77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906";
            DoTestVector("", "", 16, 1, 1, 64);
        }

        [Test]
        public void TestVector2()
        {
            ExpectedString =
                "FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640";
            DoTestVector("password", "NaCl", 1024, 8, 16, 64);
        }

        [Test]
        public void TestVector3()
        {
            ExpectedString =
                "7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887";
            DoTestVector("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64);
        }

        [Test, Ignore("This test takes a very long time")]
        public void TestVector4()
        {
            ExpectedString =
                "2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4";
            DoTestVector("pleaseletmein", "SodiumChloride", 1048576,
                8, 1, 64);
        }
    }

    [TestFixture]
    internal class PBKDFBlake3Test : PBKDFBlake3TestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            const string ctxString = "BLAKE3 2019-12-27 16:29:52 test vectors context";
            ctx = Converters.ConvertStringToBytes(ctxString, Encoding.UTF8);
            fullInput = Enumerable.Range(0, 1 << 15).Select(i => (byte) (i % 251)).ToArray();
            ByteCount = 32;
            KdfInstance =
                HashFactory.KDF.PBKDFBlake3.CreatePBKDFBlake3(ZeroByteArray, ZeroByteArray);
        }

        [Test]
        public void TestNullKeyThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDFBlake3.CreatePBKDFBlake3(NullBytes, ctx));

        [Test]
        public void TestNullContextThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDFBlake3.CreatePBKDFBlake3(ZeroByteArray, NullBytes));

        [Test]
        public void TestCheckTestVectors()
        {
            foreach (var vector in Blake3TestVectors.Blake3Vectors)
            {
                var chunkedInput = new byte[Convert.ToInt32(vector[0])];
                Array.Copy(fullInput, chunkedInput, chunkedInput.Length);

                KdfInstance = HashFactory.KDF.PBKDFBlake3.CreatePBKDFBlake3(chunkedInput, ctx);

                var output = KdfInstance.GetBytes(vector[3].Length >> 1);

                AssertAreEqual(output, Converters.ConvertHexStringToBytes(vector[3]),
                    "test vector mismatch");
            }
        }

        [Test]
        public async Task TestCheckTestVectorsAsync()
        {
            foreach (var vector in Blake3TestVectors.Blake3Vectors)
            {
                var chunkedInput = new byte[Convert.ToInt32(vector[0])];
                Array.Copy(fullInput, chunkedInput, chunkedInput.Length);

                KdfInstance = HashFactory.KDF.PBKDFBlake3.CreatePBKDFBlake3(chunkedInput, ctx);

                var output = await KdfInstance.GetBytesAsync(vector[3].Length >> 1);

                AssertAreEqual(output, Converters.ConvertHexStringToBytes(vector[3]),
                    "test vector mismatch");
            }
        }
    }

    [TestFixture]
    internal class PBKDFArgon2Test : PBKDFArgon2TestBase
    {
        private static byte[] password => Converters.ConvertStringToBytes("password", Encoding.UTF8);
        private static byte[] differentpassword => Converters.ConvertStringToBytes("differentpassword", Encoding.UTF8);

        private static byte[] salt => Converters.ConvertStringToBytes("salt", Encoding.UTF8);
        private static byte[] diffsalt => Converters.ConvertStringToBytes("diffsalt", Encoding.UTF8);
        private static byte[] somesalt => Converters.ConvertStringToBytes("somesalt", Encoding.UTF8);

        [OneTimeSetUp]
        public void Setup()
        {
            Password = GenerateRepeatingBytes(0x1, 32);
            Salt = GenerateRepeatingBytes(0x2, 16);
            Secret = GenerateRepeatingBytes(0x3, 8);
            Additional = GenerateRepeatingBytes(0x4, 12);
            ByteCount = 32;
            Builder = Argon2ParametersBuilder.DefaultBuilder()
                .WithIterations(3)
                .WithMemoryAsKiB(32)
                .WithParallelism(4)
                .WithAdditional(Additional)
                .WithSecret(Secret)
                .WithSalt(Salt);

            KdfInstance =
                HashFactory.KDF.PBKDFArgon2.CreatePBKDFArgon2(Password,
                    Argon2ParametersBuilder.DefaultBuilder().Build());
        }

        [Test]
        public void TestNullPasswordThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDFArgon2.CreatePBKDFArgon2(NullBytes, Builder.Build()));

        [Test]
        public void TestNullParameterInstanceThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDFArgon2.CreatePBKDFArgon2(ZeroByteArray, null));

        [Test]
        public void TestVectorsFromInternetDraftOne()
        {
            ExpectedString = "512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB";
            Builder
                .WithIterations(3)
                .WithMemoryAsKiB(32)
                .WithParallelism(4)
                .WithSalt(Salt)
                .WithSecret(Secret)
                .WithAdditional(Additional)
                .WithType(Argon2Type.DataDependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(Password);
        }

        [Test]
        public void TestVectorsFromInternetDraftTwo()
        {
            ExpectedString = "C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8";
            Builder
                .WithIterations(3)
                .WithMemoryAsKiB(32)
                .WithParallelism(4)
                .WithSalt(Salt)
                .WithSecret(Secret)
                .WithAdditional(Additional)
                .WithVersion(Argon2Version.Nineteen)
                .WithType(Argon2Type.DataIndependentAddressing);
            DoTestVector(Password);
        }

        [Test]
        public void TestVectorsFromInternetDraftThree()
        {
            ExpectedString = "0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659";
            Builder
                .WithIterations(3)
                .WithMemoryAsKiB(32)
                .WithParallelism(4)
                .WithSalt(Salt)
                .WithSecret(Secret)
                .WithAdditional(Additional)
                .WithVersion(Argon2Version.Nineteen)
                .WithType(Argon2Type.HybridAddressing);
            DoTestVector(Password);
        }

        [Test]
        public void TestOtherVectorsOne()
        {
            ExpectedString = "F6C4DB4A54E2A370627AFF3DB6176B94A2A209A62C8E36152711802F7B30C694";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsTwo()
        {
            ExpectedString = "9690EC55D28D3ED32562F2E73EA62B02B018757643A2AE6E79528459DE8106E9";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(20)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsThree()
        {
            ExpectedString = "3E689AAA3D28A77CF2BC72A51AC53166761751182F1EE292E3F677A7DA4C2467";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(18)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsFour()
        {
            ExpectedString = "FD4DD83D762C49BDEAF57C47BDCD0C2F1BABF863FDEB490DF63EDE9975FCCF06";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(8)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsFive()
        {
            ExpectedString = "B6C11560A6A9D61EAC706B79A2F97D68B4463AA3AD87E00C07E2B01E90C564FB";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(8)
                .WithParallelism(2)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsSix()
        {
            ExpectedString = "81630552B8F3B1F48CDB1992C4C678643D490B2B5EB4FF6C4B3438B5621724B2";
            Builder
                .WithIterations(1)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsSeven()
        {
            ExpectedString = "F212F01615E6EB5D74734DC3EF40ADE2D51D052468D8C69440A3A1F2C1C2847B";
            Builder
                .WithIterations(4)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsEight()
        {
            ExpectedString = "E9C902074B6754531A3A0BE519E5BAF404B30CE69B3F01AC3BF21229960109A3";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(differentpassword);
        }

        [Test]
        public void TestOtherVectorsNine()
        {
            ExpectedString = "79A103B90FE8AEF8570CB31FC8B22259778916F8336B7BDAC3892569D4F1C497";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(diffsalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsTen()
        {
            ByteCount = 112;
            ExpectedString =
                "1A097A5D1C80E579583F6E19C7E4763CCB7C522CA85B7D58143738E12CA39F8E6E42734C950FF2463675B97C37BA"
                + "39FEBA4A9CD9CC5B4C798F2AAF70EB4BD044C8D148DECB569870DBD923430B82A083F284BEAE777812CCE18CDAC68EE8CCEF"
                + "C6EC9789F30A6B5A034591F51AF830F4";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(diffsalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Sixteen);
            DoTestVector(password);
            ByteCount = 32;
        }

        [Test]
        public void TestOtherVectorsEleven()
        {
            ExpectedString = "C1628832147D9720C5BD1CFD61367078729F6DFB6F8FEA9FF98158E0D7816ED0";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsTwelve()
        {
            ExpectedString = "D1587ACA0922C3B5D6A83EDAB31BEE3C4EBAEF342ED6127A55D19B2351AD1F41";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(20)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsThirteen()
        {
            ExpectedString = "296DBAE80B807CDCEAAD44AE741B506F14DB0959267B183B118F9B24229BC7CB";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(18)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsFourteen()
        {
            ExpectedString = "89E9029F4637B295BEB027056A7336C414FADD43F6B208645281CB214A56452F";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(8)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsFifteen()
        {
            ExpectedString = "4FF5CE2769A1D7F4C8A491DF09D41A9FBE90E5EB02155A13E4C01E20CD4EAB61";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(8)
                .WithParallelism(2)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsSixteen()
        {
            ExpectedString = "D168075C4D985E13EBEAE560CF8B94C3B5D8A16C51916B6F4AC2DA3AC11BBECF";
            Builder
                .WithIterations(1)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsSeventeen()
        {
            ExpectedString = "AAA953D58AF3706CE3DF1AEFD4A64A84E31D7F54175231F1285259F88174CE5B";
            Builder
                .WithIterations(4)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test]
        public void TestOtherVectorsEighteen()
        {
            ExpectedString = "14AE8DA01AFEA8700C2358DCEF7C5358D9021282BD88663A4562F59FB74D22EE";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(somesalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(differentpassword);
        }

        [Test]
        public void TestOtherVectorsNineteen()
        {
            ExpectedString = "B0357CCCFBEF91F3860B0DBA447B2348CBEFECADAF990ABFE9CC40726C521271";
            Builder
                .WithIterations(2)
                .WithMemoryPowOfTwo(16)
                .WithParallelism(1)
                .WithSalt(diffsalt)
                .WithAdditional(ZeroByteArray)
                .WithSecret(ZeroByteArray)
                .WithType(Argon2Type.DataIndependentAddressing)
                .WithVersion(Argon2Version.Nineteen);
            DoTestVector(password);
        }

        [Test, Ignore("This is for manual inspection of memory use")]
        public async Task LookForMemoryLeaks()
        {
            for (var idx = 0; idx < 15000; idx++)
            {
                await HashAsync("TestPassword", "TestSalt");
                GC.Collect();
            }
        }

        private static async Task HashAsync(string passwordString, string saltString)
        {
            var saltBytes = Encoding.UTF8.GetBytes(saltString);
            var passwordBytes = Encoding.UTF8.GetBytes(passwordString);

            var builder = Argon2ParametersBuilder.DefaultBuilder()
                .WithIterations(40)
                .WithMemoryAsKiB(8192)
                .WithParallelism(16)
                .WithSalt(saltBytes);

            var pbkdfArgon2 = HashFactory.KDF.PBKDFArgon2.CreatePBKDFArgon2(passwordBytes, builder.Build());
            await pbkdfArgon2.GetBytesAsync(128);
        }
    }
}