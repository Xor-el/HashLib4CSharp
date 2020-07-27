using System;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Params;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    internal class Blake2BTest : Blake2CryptoAlgorithmTestBase
    {
        // https://docs.python.org/3/library/hashlib.html#tree-mode
        private const string Blake2BTreeHashingMode =
            "3AD2A9B37C6070E374C7A8C508FE20CA86B6ED54E286E93A0318E95E881DB5AA";

        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateBlake2B();
            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2B(new Blake2BConfig(64)
                {Key = ZeroToSixtyThreeBytes});
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE";
            HashOfDefaultData =
                "154F99998573B5FC21E3DF86EE1E0161A6E0E912C4361088FE46D2E3543070EFE9746E326BC09E77EC06BCA60955538821C010411B4D0D6BF9BF2D2221CC8017";
            HashOfOneToNine =
                "F5AB8BAFA6F2F72B431188AC38AE2DE7BB618FB3D38B6CBF639DEFCDD5E10A86B22FCCFF571DA37E42B23B80B657EE4D936478F582280A87D6DBB1DA73F5C47D";
            HashOfSmallLettersAToE =
                "F3E89A60EC4B0B1854744984E421D22B82F181BD4601FB9B1726B2662DA61C29DFF09E75814ACB2639FD79E56616E55FC135F8476F0302B3DC8D44E082EB83A8";
            HashOfDefaultDataHMACWithShortKey =
                "945EF4F96C681CC9C30A3EB1193FA13FD4ACD87D7C4A86D62AC9D8DCA74A32BB0DDC055EA75383A653E06B8E25266154DE5BE6B23C69723B795A1680EE844834";
            HashOfDefaultDataHMACWithLongKey =
                "0D70DA6A592E53ADD0900A00A2F1181198B349114D6D089B48BDAE8C2F287617D71FBCEFB375C4EB91222D96407E24DF1C1770CF88FFFDD341DC75D43E562D7E";

            KeyedTestVectors = Blake2BTestVectors.KeyedBlake2B;
            UnKeyedTestVectors = Blake2BTestVectors.UnKeyedBlake2B;
        }

        [Test]
        public void TestUnKeyedVsEmptyKeyAreSame()
        {
            for (var idx = 1; idx < 64; idx++)
            {
                var UnKeyedConfig = new Blake2BConfig(idx);
                var EmptyKeyConfig = new Blake2BConfig(idx) {Key = ZeroByteArray};

                ExpectedString = HashFactory.Crypto.CreateBlake2B(UnKeyedConfig)
                    .ComputeBytes(DefaultDataBytes).ToString();

                ActualString = HashFactory.Crypto.CreateBlake2B(EmptyKeyConfig)
                    .ComputeBytes(DefaultDataBytes).ToString();

                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public void TestBlake2BTreeHashingMode()
        {
            const byte FAN_OUT = 2;
            const byte MAX_DEPTH = 2;
            const byte INNER_SIZE = 64;
            const uint LEAF_SIZE = 4096;

            var buffer = new byte[6000];
            // Left leaf
            var treeConfigh00 = new Blake2BTreeConfig
            {
                FanOut = FAN_OUT,
                MaxDepth = MAX_DEPTH,
                LeafSize = LEAF_SIZE,
                InnerHashSize = INNER_SIZE,
                NodeOffset = 0,
                NodeDepth = 0,
                IsLastNode = false
            };
            var h00 = HashFactory.Crypto.CreateBlake2B(Blake2BConfig.DefaultConfig, treeConfigh00);
            h00.Initialize();

            // Right leaf
            var treeConfigh01 = new Blake2BTreeConfig
            {
                FanOut = FAN_OUT,
                MaxDepth = MAX_DEPTH,
                LeafSize = LEAF_SIZE,
                InnerHashSize = INNER_SIZE,
                NodeOffset = 1,
                NodeDepth = 0,
                IsLastNode = true
            };
            var h01 = HashFactory.Crypto.CreateBlake2B(Blake2BConfig.DefaultConfig, treeConfigh01);
            h01.Initialize();

            // Root node
            var treeConfigh10 = new Blake2BTreeConfig
            {
                FanOut = FAN_OUT,
                MaxDepth = MAX_DEPTH,
                LeafSize = LEAF_SIZE,
                InnerHashSize = INNER_SIZE,
                NodeOffset = 0,
                NodeDepth = 1,
                IsLastNode = true
            };
            var h10 = HashFactory.Crypto.CreateBlake2B(new Blake2BConfig(32), treeConfigh10);
            h10.Initialize();

            var temp = new byte[LEAF_SIZE];
            Array.Copy(buffer, temp, temp.Length);
            h10.TransformBytes(h00.ComputeBytes(temp).GetBytes());

            temp = new byte[buffer.Length - LEAF_SIZE];
            Array.Copy(buffer, LEAF_SIZE, temp, 0, temp.Length);
            h10.TransformBytes(h01.ComputeBytes(temp).GetBytes());

            ExpectedString = Blake2BTreeHashingMode;
            ActualString = h10.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal class Blake2BPTest : Blake2CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateBlake2BP(64, ZeroByteArray);
            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2BP(64, ZeroToSixtyThreeBytes);
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "B5EF811A8038F70B628FA8B294DAAE7492B1EBE343A80EAABBF1F6AE664DD67B9D90B0120791EAB81DC96985F28849F6A305186A85501B405114BFA678DF9380";
            HashOfDefaultData =
                "6F02764BDBA4184E50CAA52539BC392239D31E1BC76CEACBCA42630BCB7B48B527F65AA2F50363C0E26A287B758C87BC77C7175AB7A12B33104330F5A1C6E171";
            HashOfOneToNine =
                "E70843E71EF73EF84D991990687CB72E272E590F7E86F491935E9904F0582A165A388F956D691101C5D2B035634E4415C3CB21D7F721702CC64791D53AEDB9E2";
            HashOfSmallLettersAToE =
                "C96CA7B60257D18A67EC6DAF4E06A6A0F882ECEE22605DBE64DFAD2D7AA2FF939726385C7E60F00A2A38CF302E460C33EAE769CA5652FA8456EA6A75DC6AAC39";
            HashOfDefaultDataHMACWithShortKey =
                "671A8EE18AD7BCC940CF4B35B47D0AAA89077AA8503E4E374A5BC2803758BBF04C6C80F97E5B71CD79A1E6DCD6585EB82A5F5482DB268B462D651530CE5CB177";
            HashOfDefaultDataHMACWithLongKey =
                "5FBB74E2A06A9D10762E3B2BD2ECC3B0E83F2FB1652D6F55E426D59354DF3803583E055318762DEF415DE98E441DC153263857B08D5F2462753872E663C13D5C";

            KeyedTestVectors = Blake2BPTestVectors.KeyedBlake2BP;
            UnKeyedTestVectors = Blake2BPTestVectors.UnKeyedBlake2BP;
        }
    }

    internal class Blake2STest : Blake2CryptoAlgorithmTestBase
    {
        // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2s
        private const string Blake2STreeHashingMode =
            "C81CD326CA1CA6F40E090A9D9E738892";

        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateBlake2S();
            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2S(new Blake2SConfig(32)
                {Key = ZeroToThirtyOneBytes});
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9";
            HashOfDefaultData =
                "D9DB23D51529BC163546C2C76F9FDC4611118A691352524D6BCCF5C79AF89E14";
            HashOfOneToNine =
                "7ACC2DD21A2909140507F37396ACCE906864B5F118DFA766B107962B7A82A0D4";
            HashOfSmallLettersAToE =
                "4BD7246C13721CC5B96F045BE71D49D5C82535332C6903771AFE9EF7B772136F";
            HashOfDefaultDataHMACWithShortKey =
                "105C7994CB1F775C709A9FBC9641FB2495311258268134F460B9895915A7519A";
            HashOfDefaultDataHMACWithLongKey =
                "2FF5605B8269DE6FA04C03CD30C8C48838605C639A38EBF42A93830CE7CA5E57";

            KeyedTestVectors = Blake2STestVectors.KeyedBlake2S;
            UnKeyedTestVectors = Blake2STestVectors.UnKeyedBlake2S;
        }

        [Test]
        public void TestUnKeyedVsEmptyKeyAreSame()
        {
            for (var idx = 1; idx < 32; idx++)
            {
                var UnKeyedConfig = new Blake2SConfig(idx);
                var EmptyKeyConfig = new Blake2SConfig(idx) {Key = ZeroByteArray};

                ExpectedString = HashFactory.Crypto.CreateBlake2S(UnKeyedConfig)
                    .ComputeBytes(DefaultDataBytes).ToString();

                ActualString = HashFactory.Crypto.CreateBlake2S(EmptyKeyConfig)
                    .ComputeBytes(DefaultDataBytes).ToString();

                AssertAreEqual(ExpectedString, ActualString);
            }
        }

        [Test]
        public void TestBlake2STreeHashingMode()
        {
            const byte FAN_OUT = 2;
            const byte MAX_DEPTH = 2;
            const byte INNER_SIZE = 32;
            const uint LEAF_SIZE = 4096;

            var buffer = new byte[6000];
            // Left leaf
            var treeConfigh00 = new Blake2STreeConfig
            {
                FanOut = FAN_OUT,
                MaxDepth = MAX_DEPTH,
                LeafSize = LEAF_SIZE,
                InnerHashSize = INNER_SIZE,
                NodeOffset = 0,
                NodeDepth = 0,
                IsLastNode = false
            };
            var h00 = HashFactory.Crypto.CreateBlake2S(Blake2SConfig.DefaultConfig, treeConfigh00);
            h00.Initialize();

            // Right leaf
            var treeConfigh01 = new Blake2STreeConfig
            {
                FanOut = FAN_OUT,
                MaxDepth = MAX_DEPTH,
                LeafSize = LEAF_SIZE,
                InnerHashSize = INNER_SIZE,
                NodeOffset = 1,
                NodeDepth = 0,
                IsLastNode = true
            };
            var h01 = HashFactory.Crypto.CreateBlake2S(Blake2SConfig.DefaultConfig, treeConfigh01);
            h01.Initialize();

            // Root node
            var treeConfigh10 = new Blake2STreeConfig
            {
                FanOut = FAN_OUT,
                MaxDepth = MAX_DEPTH,
                LeafSize = LEAF_SIZE,
                InnerHashSize = INNER_SIZE,
                NodeOffset = 0,
                NodeDepth = 1,
                IsLastNode = true
            };
            var h10 = HashFactory.Crypto.CreateBlake2S(new Blake2SConfig(16), treeConfigh10);
            h10.Initialize();

            var temp = new byte[LEAF_SIZE];
            Array.Copy(buffer, temp, temp.Length);
            h10.TransformBytes(h00.ComputeBytes(temp).GetBytes());

            temp = new byte[buffer.Length - LEAF_SIZE];
            Array.Copy(buffer, LEAF_SIZE, temp, 0, temp.Length);
            h10.TransformBytes(h01.ComputeBytes(temp).GetBytes());

            ExpectedString = Blake2STreeHashingMode;
            ActualString = h10.TransformFinal().ToString();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal class Blake2SPTest : Blake2CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateBlake2SP(32, ZeroByteArray);
            HashInstanceWithKey = HashFactory.Crypto.CreateBlake2SP(32, ZeroToThirtyOneBytes);
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "DD0E891776933F43C7D032B08A917E25741F8AA9A12C12E1CAC8801500F2CA4F";
            HashOfDefaultData =
                "F1617895134C203ED0A9C8CC72938161EBC9AB6F233BBD3CCFC4D4BCA08A5ED0";
            HashOfOneToNine =
                "D6D3157BD4E809982E0EEA22C5AF5CDDF05473F6ECBE353119591E6CDCB7127E";
            HashOfSmallLettersAToE =
                "107EEF69D795B14C8411EEBEFA897429682108397680377C78E5D214F014916F";
            HashOfDefaultDataHMACWithShortKey =
                "D818A87A70949BDA7DE9765650D665C49B1B5CF11B05A1780901C46A91FFD786";
            HashOfDefaultDataHMACWithLongKey =
                "989E63ED61D8A5D1F55A534C4835129924B28F6E41AE7924596A8874CF4082F6";

            KeyedTestVectors = Blake2SPTestVectors.KeyedBlake2SP;
            UnKeyedTestVectors = Blake2SPTestVectors.UnKeyedBlake2SP;
        }
    }

    internal class Blake3Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateBlake3_256(ZeroByteArray);
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262";
            HashOfDefaultData =
                "BB8DB7E4155BFDB254AD49D8D3105C57B6AC3E783E6D316A75E8B8F8911EB41F";
            HashOfOneToNine =
                "B7D65B48420D1033CB2595293263B6F72EABEE20D55E699D0DF1973B3C9DEED1";
            HashOfSmallLettersAToE =
                "0648C03B5AD9BB6DDF8306EEF6A33EBAE8F89CB4741150C1AE9CD662FDCC1EE2";
            HashOfDefaultDataHMACWithShortKey =
                "D4DE3C2DE89625AF7076FEC6CFD7B0D318665514D1F88CF68F567AC4971B6681";
            HashOfDefaultDataHMACWithLongKey =
                "BF524C4BA2B002AB0E4F2BDF366EC980C7F8422D1DAF49B7FF660054B27B9FA8";
        }
    }

    [TestFixture]
    internal class GostTest : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateGost();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D";
            HashOfDefaultData = "21DCCFBF20D313170333BA15596338FB5964267328EB42CA10E269B7045FF856";
            HashOfOneToNine = "264B4E433DEE474AEC465FA9C725FE963BC4B4ABC4FDAC63B7F73B671663AFC9";
            HashOfSmallLettersAToE = "B18CFD04F92DC1D83325036BC723D36DB25EDE41AE879D2545FC7F377B700899";
            HashOfDefaultDataHMACWithShortKey = "6E4E2895E194BEB0A083B1DED6C4084F5E7F37BAAB988D288D9707235F2F8294";
            HashOfDefaultDataHMACWithLongKey = "604D7D95D281CFFB5139F8C6C46A9E035CC65D75C3D37F8755D860C92D3F21B3";
        }
    }

    [TestFixture]
    internal class GOST3411_2012_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateGOST3411_2012_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB";
            HashOfDefaultData = "9CAC7A67CC162B3860E289849EF463B0EBA83138E974011CE1640CFE7869960A";
            HashOfOneToNine = "84DA1066A0205E1446EC4A858ED2314B6233E5790BA5999DDE8CD35D5D39F002";
            HashOfSmallLettersAToE = "DDA887AF02D8C39E0138BD4B95F8CF0DDAF7CD4637FCB94D55BB4003339EC01E";
            HashOfDefaultDataHMACWithShortKey = "DD3972BF0032672E7BC09F62D07A3101A499829D5EF539CA805E2226C59EF493";
            HashOfDefaultDataHMACWithLongKey = "C4683CC1DE501C728483608FE132614F04671618EA112C2B4BAF710154E0DA8A";
        }
    }

    [TestFixture]
    internal class GOST3411_2012_512Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateGOST3411_2012_512();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A";
            HashOfDefaultData =
                "48D298A6C02F7D4F0E576CEA2C6AE32E172CDA3B623E1B4ACE8993383FB0562C2D4B34A6FC16FA31B4162827202366E4425BA745B2D2F8195800A8D35DC32EE7";
            HashOfOneToNine =
                "C36FADF5238435A7DDA541152C70014A3C2FF0211BBA50F15D2279BA13F6F1E4F4108C6B39FC12CA93E73453A95A135BFF756312165FC8E4C159DFD6F3A4BAF6";
            HashOfSmallLettersAToE =
                "C867AA7F3946FF1247CE937F49023871E400DD58E6615DC862597C018BB9C95200620B705624BD0F853521574D6A62721DE7A433719B403B6173AD710F20B219";
            HashOfDefaultDataHMACWithShortKey =
                "AE0EF8058199079EA6D77DE161E843582F2F2EFA744BAB262462041AD0BDA125E300C4D203D1BCB89161AF35CD581C3EE0C26A8A71A7D8ED4E73EEDC91F75B59";
            HashOfDefaultDataHMACWithLongKey =
                "867472A90F377859D896DE56DF3A5C4ECB4AFA9E8832A2430C537707E4E29FA1F991A814AA8914DD65A144EDB25FAAC2AEEB6667C559D8D8D82CDF45A7F2F664";
        }
    }

    [TestFixture]
    internal class Grindahl256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateGrindahl256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "45A7600159AF54AE110FCB6EA0F38AD57875EAC814F74D2CBC247D28C89923E6";
            HashOfDefaultData = "AC72E90B0F3F5864A0AF3C43E2A73E393DEBF22AB81B6786ADE22B4517DAAAB6";
            HashOfOneToNine = "D2460846C5FE9E4750985CC9244D2458BEFD884435121FE56528022A3C7605B7";
            HashOfSmallLettersAToE = "5CDA73422F36E41087795BB6C21D577BAAF114E4A6CCF33D919E700EE2489FE2";
            HashOfDefaultDataHMACWithShortKey = "65BA6F8EFA5B566D556EC8E3A2EC67DB7EE9BDEE663F17A8B8E7FAD067481023";
            HashOfDefaultDataHMACWithLongKey = "00514B24C3AE4358B0C6D5CECDE33078E800E4A54369CB2E75C68A2CCE82FDAF";
        }
    }

    [TestFixture]
    internal class Grindahl512Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateGrindahl512();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "EE0BA85F90B6D232430BA43DD0EDD008462591816962A355602ED214FAAE54A9A4607D6F577CE950421FF58AEA53F51A7A9F5CCA894C3776104D43568FEA1207";
            HashOfDefaultData =
                "540F3C6A5070DA391BBA7121DB8F8745752D3515164498FC82CB5B4D837632CF3F256D85C4A0B7F34A86936FAB07BDA2DF2BFDD59AFDBD901E1347C2001DB1AD";
            HashOfOneToNine =
                "6845F20B8A9DB083F307844506D342ED0FEE0D16BAF64B22E6C07552CB8C907E936FEDCD885B72C1B05813F722B5706C112AD59D3421CFD88CAA1CFB40EF1BEF";
            HashOfSmallLettersAToE =
                "F282C47F31831EAB58B8EE9D1EEE3B9B5A6A86354EEFE84CA3176BED5AB447E6D5AC82316F2D6FAAD350848E2D418336A57772D96311DA8BC51C93087204C6A5";
            HashOfDefaultDataHMACWithShortKey =
                "7F067A454A4F6300982CAE37900171C627992A75A5567E0D3A51BC6672F79C5AC0CEF5978E933B713F38494DDF26114994C47689AC93EEC9B8EF7892C3B24087";
            HashOfDefaultDataHMACWithLongKey =
                "7C678E7298C32C4964DFF1EF0EC5B2F5421669920DE067B38E4B331E8640EDE2130945C03C6CD18E2EBA0085F96BC62118ADEB0655BB9F3910CBB6EB05680CCB";
        }
    }

    [TestFixture]
    internal class HAS160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHAS160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "307964EF34151D37C8047ADEC7AB50F4FF89762D";
            HashOfDefaultData = "2773EDAC4501514254D7B1DF091D6B7652250A52";
            HashOfOneToNine = "A0DA48CCD36C9D24AA630D4B3673525E9109A83C";
            HashOfSmallLettersAToE = "EEEA94C2F0450B639BC2ACCAF4AEB172A5885313";
            HashOfDefaultDataHMACWithShortKey = "53970A7AC510A85D0E22FF506FED5B57188A8B3F";
            HashOfDefaultDataHMACWithLongKey = "5B0728FB858649658644EAD5422A48A37DC4F9F6";
        }
    }

    [TestFixture]
    internal class Haval_3_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_3_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "C68F39913F901F3DDF44C707357A7D70";
            HashOfDefaultData = "04AF7562BA75D5767ADE2A71E4BE33DE";
            HashOfOneToNine = "F2F92D4E5CA6B92A5B5FC5AC822C39D2";
            HashOfSmallLettersAToE = "51D4032478AA59182916E6C111FA79A6";
            HashOfDefaultDataHMACWithShortKey = "9D49ED7B5D42C64F590A164C5D1AAE9F";
            HashOfDefaultDataHMACWithLongKey = "3A1F5639B460F24C474E6B2156175949";
        }
    }

    [TestFixture]
    internal class Haval_4_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_4_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "EE6BBF4D6A46A679B3A856C88538BB98";
            HashOfDefaultData = "C815192C498CF266D0EB32E90D60892E";
            HashOfOneToNine = "52DFE2F3DA02591061B02DBDC1510F1C";
            HashOfSmallLettersAToE = "61634059D9B8336FEB32CA27533ED284";
            HashOfDefaultDataHMACWithShortKey = "9A0B60DEB9F9FBB2A9DAD87A8C653E72";
            HashOfDefaultDataHMACWithLongKey = "25E4295BCDCCB26A1F8E5982685E44C2";
        }
    }

    [TestFixture]
    internal class Haval_5_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_5_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "184B8482A0C050DCA54B59C7F05BF5DD";
            HashOfDefaultData = "B335D2DC38EFB9D937B803F7581AF88D";
            HashOfOneToNine = "8AA1C1CA3A7E4F983654C4F689DE6F8D";
            HashOfSmallLettersAToE = "11C0532F713332D45D6769376DD6EB3B";
            HashOfDefaultDataHMACWithShortKey = "1D5D93E71FF0B324C54ADD1FBDE1F4E4";
            HashOfDefaultDataHMACWithLongKey = "931DFA421EB8538C9713C453D47B916D";
        }
    }

    [TestFixture]
    internal class Haval_3_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_3_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "D353C3AE22A25401D257643836D7231A9A95F953";
            HashOfDefaultData = "4A5E28CA30029D2D04287E6C807E74D297A7FC74";
            HashOfOneToNine = "39A83AF3293CDAC04DE1DF3D0BE7A1F9D8AAB923";
            HashOfSmallLettersAToE = "8D7C2218BDD8CB0608BA2479751B44BB15F1FC1F";
            HashOfDefaultDataHMACWithShortKey = "E686A2E785EA222FA28911D9243567EB72362D3C";
            HashOfDefaultDataHMACWithLongKey = "89544E2BE8334B7949D537666376F880DBDE661E";
        }
    }

    [TestFixture]
    internal class Haval_4_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_4_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "1D33AAE1BE4146DBAACA0B6E70D7A11F10801525";
            HashOfDefaultData = "9E86A9E2D964CCF9019593C88F40AA5C725E0912";
            HashOfOneToNine = "B03439BE6F2A3EBED93AC86846D029D76F62FD99";
            HashOfSmallLettersAToE = "F74B326FE2CE8F5BA151B85B16E67B28FE71F131";
            HashOfDefaultDataHMACWithShortKey = "6FEAC0105DA74AEDC8FA76A1CF0848C8CA94BA28";
            HashOfDefaultDataHMACWithLongKey = "EC603B78FA4F7440713E95594CE903700D1E742C";
        }
    }

    [TestFixture]
    internal class Haval_5_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_5_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "255158CFC1EED1A7BE7C55DDD64D9790415B933B";
            HashOfDefaultData = "A9AB9AB152BB4413B717228C3A65E75644542A35";
            HashOfOneToNine = "11F592B3A1A1A9C0F9C638C33B69E442D06C1D99";
            HashOfSmallLettersAToE = "53734616DD6761E2A1D2BD520035287972625385";
            HashOfDefaultDataHMACWithShortKey = "A0FFFE2DE177281E64C5D0A9DC81BFFDF14F6031";
            HashOfDefaultDataHMACWithLongKey = "6D89A1E48CD36DBD8D3164FBBF663AC009A74A62";
        }
    }

    [TestFixture]
    internal class Haval_3_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_3_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E";
            HashOfDefaultData = "4235822851EB1B63D6B1DB56CF18EBD28E0BC2327416D5D1";
            HashOfOneToNine = "6B92F078E73AF2E0F9F049FAA5016D32173A3D62D2F08554";
            HashOfSmallLettersAToE = "4A106D88931B60DF1BA352782141C473E79019022D65D7A5";
            HashOfDefaultDataHMACWithShortKey = "3E72C9200EAA6ED8D2EF60B8773BAF147A94E98A1FF4E70B";
            HashOfDefaultDataHMACWithLongKey = "45F08819482AC1815F23D8E94C71288461C6B795A5532B86";
        }
    }

    [TestFixture]
    internal class Haval_4_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_4_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA";
            HashOfDefaultData = "54D4FD0DE4228D55F826B627A128A765378B1DC1F8E6CD75";
            HashOfOneToNine = "A5C285EAD0FF2F47C15C27B991C4A3A5007BA57137B18D07";
            HashOfSmallLettersAToE = "88A58D9011CA363A3F3CD113FFEAA44870C07CC14E94FB1B";
            HashOfDefaultDataHMACWithShortKey = "8AB3C2ED5E17CC15EE9D0740185BFFC53C054BC71B9A44AA";
            HashOfDefaultDataHMACWithLongKey = "93CA56E975624D12441792646EEE40221BDD02FFD647E148";
        }
    }

    [TestFixture]
    internal class Haval_5_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_5_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85";
            HashOfDefaultData = "ED197F026B20DB6362CBC62BDD28E0B34F1E287966D84E3B";
            HashOfOneToNine = "EC32312AA79775539675C9BA83D079FFC7EA498FA6173A46";
            HashOfSmallLettersAToE = "CDDF16E273A09E9E2F1D7D4761C2D35E1DD6EE327F1F5AFD";
            HashOfDefaultDataHMACWithShortKey = "AB2C407C403A82EEADF2A0B3F4B66B34A12322159E7A95B6";
            HashOfDefaultDataHMACWithLongKey = "22BFD1AB474792284D01139B7BEA6F16B0E6AB1C39FFFF0A";
        }
    }

    [TestFixture]
    internal class Haval_3_224Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_3_224();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D";
            HashOfDefaultData = "12B7BFA1D36D0163E876A1474EB33CF5BC24C1BBBB181F28ACEE8D36";
            HashOfOneToNine = "28E8CC65356B43ACBED4DD70F11D0827F17C4442D323AAA0A0DE285F";
            HashOfSmallLettersAToE = "177DA8770D5BF50E1B5D82DD60DF2635102D490D86F876E70F7A4080";
            HashOfDefaultDataHMACWithShortKey = "2C403CCE41533900919919CA9B8A637AEC0A1E1F7FA154F978592B6B";
            HashOfDefaultDataHMACWithLongKey = "87DD7EFF74325F4B27D09E1C5CC9729A4881C549A20E7450E8316606";
        }
    }

    [TestFixture]
    internal class Haval_4_224Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_4_224();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E";
            HashOfDefaultData = "DA7AB9D08D42C1819C04C7064891DB700DD05C960C3192CB615758B0";
            HashOfOneToNine = "9A08D0CF1D52BB1AC22F6421CFB902E700C4C496B3E990F4606F577D";
            HashOfSmallLettersAToE = "3EEF5DC9C3B3DE0F142DB08B89C21A1FDB1C64D7B169425DBA161190";
            HashOfDefaultDataHMACWithShortKey = "334328027BA2D8F218F8BF374853252D3150FA774D0CBD6F674AEFE0";
            HashOfDefaultDataHMACWithLongKey = "4BC107815803C88FB710307CBFEF058E9DE3CC658F06458DADB330C5";
        }
    }

    [TestFixture]
    internal class Haval_5_224Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_5_224();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E";
            HashOfDefaultData = "D5FEA825ED7B8CBF23938425BAFDBEE9AD127A685EFCA4559BD54892";
            HashOfOneToNine = "2EAADFB8007D9A4D8D7F21182C2913D569F801B44D0920D4CE8A01F0";
            HashOfSmallLettersAToE = "D8CBE8D06DC58095EC0E69F1C1A4D4A90893AAE80401779CEB6646A9";
            HashOfDefaultDataHMACWithShortKey = "12B6415C63F4BBA34F0ADD23EEB74AC7EE8A07420D652BF619B9E9D1";
            HashOfDefaultDataHMACWithLongKey = "CFA8D05FEE7A22F7A2BBDF3A218157910FB682517421A416C6DE0895";
        }
    }

    [TestFixture]
    internal class Haval_3_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_3_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17";
            HashOfDefaultData = "9AA25FF9D7559F108E01014C27EBEEA34E8D82BD1A6105D28A53791B74C4C024";
            HashOfOneToNine = "63E8D0AEEC87738F1E820294CBDF7961CD2246B3620B4BAC81BE0B9827D612C7";
            HashOfSmallLettersAToE = "3913AB70F6219EEFE10B202DE5991EFDBC4A808203BD60BBFBFC043383AE8F90";
            HashOfDefaultDataHMACWithShortKey = "7E24B475617096B102F0F64572E297144B35683476D1768CB35C0E0A43A6BF8F";
            HashOfDefaultDataHMACWithLongKey = "AB74FDDE53C599E20D13D98AF52E15FD4804C038A1C48060B9F078F3585C23F3";
        }
    }

    [TestFixture]
    internal class Haval_4_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_4_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B";
            HashOfDefaultData = "B5E97F406CBD4C36CC549072713E733EE31A5F9F23DD6C5982D3A239A9B38434";
            HashOfOneToNine = "DDC95DF473DD169456484BEB4B04EDCA83A5572D9D7ECCD00092365AE4EF8D79";
            HashOfSmallLettersAToE = "8F9B46785E52C6C48A0178EDC66D3C23C220D15E52C3C8A13E1CD45D21369193";
            HashOfDefaultDataHMACWithShortKey = "FD0122B375A581D3F06DB6EB992F9A3F46657091E427BB8BD247D835CC086437";
            HashOfDefaultDataHMACWithLongKey = "149D5BF6ED121FE862D15409C0F40913AEEBD563CCC3F2CD74E0979A09CAC2F1";
        }
    }

    [TestFixture]
    internal class Haval_5_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateHaval_5_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330";
            HashOfDefaultData = "E5061D6F4F8645262C5C923F8E607CD77D69CE772E3DE559132B460309BFB516";
            HashOfOneToNine = "77FD61460DB5F89DEFC9A9296FAB68A1730EA6C9C0037A9793DAC8492C0A953C";
            HashOfSmallLettersAToE = "C464C9A669D5B43E4C34808114DCE4ECC732D1B71407E7F05468D0B15BFF7E30";
            HashOfDefaultDataHMACWithShortKey = "C702F985817A2596D7E0BB073D71DFEF72D77BD45599DD4F7E5D83A8EAF7268B";
            HashOfDefaultDataHMACWithLongKey = "59C3B0DAF16A8D67DE2C7A3A364AC3E65D1BE0EF61DCECC99B9D8EFA9174ACCC";
        }
    }

    [TestFixture]
    internal class Keccak_224Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateKeccak_224();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD";
            HashOfDefaultData = "1BA678212F840E95F076B4E3E75310D4DA4308E04396E07EF1683ACE";
            HashOfOneToNine = "06471DE6C635A88E7470284B2C2EBF9BD7E5E888CBBD128C21CB8308";
            HashOfSmallLettersAToE = "16F91F7E036DF526340440C34C231862D8F6319772B670EEFD4703FF";
            HashOfDefaultDataHMACWithShortKey = "D6CE783743A36717F893DFF82DE89633F21089AFBE4F26431E269650";
            HashOfDefaultDataHMACWithLongKey = "008C90CB7F25BEDF3C9C80404D37DB2DE49EA19BD1BDF9CF68BF6F48";
        }
    }

    [TestFixture]
    internal class Keccak_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateKeccak_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470";
            HashOfDefaultData = "3FE42FE8CD6DAEF5ED7891846577F56AB35DC806424FC84A494C81E73BB06B5F";
            HashOfOneToNine = "2A359FEEB8E488A1AF2C03B908B3ED7990400555DB73E1421181D97CAC004D48";
            HashOfSmallLettersAToE = "6377C7E66081CB65E473C1B95DB5195A27D04A7108B468890224BEDBE1A8A6EB";
            HashOfDefaultDataHMACWithShortKey = "1660234E7CCC29CFC8DEC8C6508AAF54EE48004EA9B56A15AC5742C89AAADA08";
            HashOfDefaultDataHMACWithLongKey = "CD39A2CEEB1FDB058F0487FEF9A74927BD7942CF01922A22E642A78FAC425870";
        }
    }

    [TestFixture]
    internal class Keccak_288Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateKeccak_288();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "6753E3380C09E385D0339EB6B050A68F66CFD60A73476E6FD6ADEB72F5EDD7C6F04A5D01";
            HashOfDefaultData = "A81F64CA8FAFFA1FC64A8E40E3F6A6FEA3303753B8F7F25E7E6EABA3D99A13F1EDF0F125";
            HashOfOneToNine = "2B87D3D1907AA78236C7037752CA8C456611C24CE8FBAAAC961AABF3137B471C93A8F031";
            HashOfSmallLettersAToE = "F996518E4703A5D660B250D720A143B0A44C5DE31819A82FEF0F30158D18E74E6DF405F6";
            HashOfDefaultDataHMACWithShortKey =
                "615143BAA85817D4F6F051E33801A900AEA480E716A01826E1392743A92B46EED587E9F7";
            HashOfDefaultDataHMACWithLongKey =
                "A38EEDE431AFA3DBD49F03A93A0B8F8838D46A166ABBC96D1F1BA936007E9C6911977608";
        }
    }

    [TestFixture]
    internal class Keccak_384Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateKeccak_384();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC006AFBFA8FE2479B2DD2B21362337441AC12B515911957FF";
            HashOfDefaultData =
                "6A53977DFA0BCDCF069635CF541AB64C7E41923FCB3A5B049AB98878411D0E71DF95FCAB0072F1AE8B931BF4490B823E";
            HashOfOneToNine =
                "EFCCAE72CE14656C434751CF737E70A57AB8DD2C76F5ABE01E52770AFFD77B66D2B80977724A00A6D971B702906F8032";
            HashOfSmallLettersAToE =
                "6E577A02A783232ACF34841399883F5F69D9AC78F48C7F4431CBC4F669C2A0F1CA3B1BECB7701B8315588D64D6C3746A";
            HashOfDefaultDataHMACWithShortKey =
                "044628643016E3EA30DE6CA3A8A1276F6BF1A5443CEF96BAA73199CF64FFC52D7F38254C671DB2933FFC8DD3E5B77223";
            HashOfDefaultDataHMACWithLongKey =
                "6EFB6A4D0FB6F1ECEF924DE91C7BB25A925B16EDB4FA7E64F153596064C6B57AC6C61A7EE463BB4C9E18E744CA313F9F";
        }
    }

    [TestFixture]
    internal class Keccak_512Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateKeccak_512();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "0EAB42DE4C3CEB9235FC91ACFFE746B29C29A8C366B7C60E4E67C466F36A4304C00FA9CAF9D87976BA469BCBE06713B435F091EF2769FB160CDAB33D3670680E";
            HashOfDefaultData =
                "27E67744299C2229F5008141E410B650BB7D70366B8A60BEAE52F8D6F4A8889D1BAEF53191FF53277FD6CFFE76937CDFAC40EB8EE6F32E3B146C05F961E970A8";
            HashOfOneToNine =
                "40B787E94778266FB196A73B7A77EDF9DE2EF172451A2B87531324812250DF8F26FCC11E69B35AFDDBE639956C96153E71363F97010BC99405DD2D77B8C41986";
            HashOfSmallLettersAToE =
                "37491BD4BF2A4629D4E35602E09812FA94BFC63BAEE4487075E2B6D73F36D01A7392A1719EDBBB5D1D6FA3BA0D144F18229ABC13B7933A4736D6AAB4A3177F18";
            HashOfDefaultDataHMACWithShortKey =
                "6FA826F0AFFE589DFD1665264F5516D076F9FEC585FD4227095B467A50E963D45C1730232549E8DDB590C1518BA310612839BBCCDF34F6A0AD6AC8B91D393BE6";
            HashOfDefaultDataHMACWithLongKey =
                "5363E877624D2B2EBB51DED66174F2DEDBEBDC679C5E6B28EC74B03AA12E4FA880B732EA38F54188114CBD720D9C0FCD5496D799D6B97280EAB5378EDA22B71B";
        }
    }

    [TestFixture]
    internal class MD2Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateMD2();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "8350E5A3E24C153DF2275C9F80692773";
            HashOfDefaultData = "DFBE28FF5A3C23CAA85BE5848F16524E";
            HashOfOneToNine = "12BD4EFDD922B5C8C7B773F26EF4E35F";
            HashOfSmallLettersAToE = "DFF9959487649F5C7AF5D0680A9A5D22";
            HashOfDefaultDataHMACWithShortKey = "C5F4625462CD5CF7723C19E8566F6790";
            HashOfDefaultDataHMACWithLongKey = "B259EC2400B72D0D5B54DC66330A1274";
        }
    }

    [TestFixture]
    internal class MD4Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateMD4();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "31D6CFE0D16AE931B73C59D7E0C089C0";
            HashOfDefaultData = "A77EAB8C3432FD9DD1B87C3C5C2E9C3C";
            HashOfOneToNine = "2AE523785D0CAF4D2FB557C12016185C";
            HashOfSmallLettersAToE = "9803F4A34E8EB14F96ADBA49064A0C41";
            HashOfDefaultDataHMACWithShortKey = "BF21F9EC05E480EEDB12AF20181713E3";
            HashOfDefaultDataHMACWithLongKey = "72F808BCE6C0E340813B3A4F6173F452";
        }
    }

    [TestFixture]
    internal class MD5Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateMD5();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "D41D8CD98F00B204E9800998ECF8427E";
            HashOfDefaultData = "462EC1E50C8F2D5C387682E98F9BC842";
            HashOfOneToNine = "25F9E794323B453885F5181F1B624D0B";
            HashOfSmallLettersAToE = "AB56B4D92B40713ACC5AF89985D4B786";
            HashOfDefaultDataHMACWithShortKey = "09F705F43799213192622CCA6DF68941";
            HashOfDefaultDataHMACWithLongKey = "676E69260120FC778A90993F915536FC";
        }
    }

    [TestFixture]
    internal class PanamaTest : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreatePanama();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "AA0CC954D757D7AC7779CA3342334CA471ABD47D5952AC91ED837ECD5B16922B";
            HashOfDefaultData = "69A05A5A5DDB32F5589257458BBDD059FB30C4486C052D81029DDB2864E90813";
            HashOfOneToNine = "3C83D2C9109DE4D1FA64833683A7C280591A7CFD8516769EA879E56A4AD39B99";
            HashOfSmallLettersAToE = "B064E5476A3F511105B75305FC2EC31578A6B200FB5084CF937C179F1C52A891";
            HashOfDefaultDataHMACWithShortKey = "3C15C9B7CDC77470BC02CA96711B66FAA976AC2044F6F177ABCA93B1442EA376";
            HashOfDefaultDataHMACWithLongKey = "F1E44ADC01E21143E284244D6A512A77907BE62D782BA4A06EA999A967A8E29B";
        }
    }

    [TestFixture]
    internal class RadioGatun32Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateRadioGatun32();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "F30028B54AFAB6B3E55355D277711109A19BEDA7091067E9A492FB5ED9F20117";
            HashOfDefaultData = "17B20CF19B3FC84FD2FFE084F07D4CD4DBBC50E41048D8259EB963B0A7B9C784";
            HashOfOneToNine = "D77629174F56D8451F73CBE80EC7A20EF2DD65C46A1480CD004CBAA96F3FA1FD";
            HashOfSmallLettersAToE = "A593059B12513A1BD88A2D433F07B239BC14743AF0FF7294837B5DF756BF9C7A";
            HashOfDefaultDataHMACWithShortKey = "72EB7D36180C1B1BBF88E062FEC7419DBB4849892623D332821C1B0D71D6D513";
            HashOfDefaultDataHMACWithLongKey = "0094642DFF72A2A3E6D2D3EC9C46A2684A77697CA63FA2AF8BE39F3D09332822";
        }
    }

    [TestFixture]
    internal class RadioGatun64Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateRadioGatun64();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "64A9A7FA139905B57BDAB35D33AA216370D5EAE13E77BFCDD85513408311A584";
            HashOfDefaultData = "43B3208CE2E6B23D985087A84BD583F713A9002280BF2785B1EE569B12C15054";
            HashOfOneToNine = "76A565017A42B258F5C8C9D2D9FD4C7347947A659ED142FF61C1BEA592F103C5";
            HashOfSmallLettersAToE = "36B4DD23A97424844662E882AD1DA1DBAD8CB435A57F380455393C9FF9DE9D37";
            HashOfDefaultDataHMACWithShortKey = "FA280F80C1323C32AACC7F1CAB3808FE2BB8880F901AE6F03BD14D6D1884B267";
            HashOfDefaultDataHMACWithLongKey = "95B3C58394EAEAA82CBE3A4D96ED88FECDEC4B7400C3D652BA0F72A1378CA4CA";
        }
    }

    [TestFixture]
    internal class RIPEMDTest : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateRIPEMD();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "9F73AA9B372A9DACFB86A6108852E2D9";
            HashOfDefaultData = "B3F629A9786744AA105A2C150869C236";
            HashOfOneToNine = "C905B44C6429AD0A1934550037D4816F";
            HashOfSmallLettersAToE = "68D2362617E85CF1BF7381DF14045DBB";
            HashOfDefaultDataHMACWithShortKey = "219ACFCF07BDB775FBA73DACE1E97E08";
            HashOfDefaultDataHMACWithLongKey = "8BE7B83BAB7882955801891800636EFE";
        }
    }

    [TestFixture]
    internal class RIPEMD128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateRIPEMD128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "CDF26213A150DC3ECB610F18F6B38B46";
            HashOfDefaultData = "75891B00B2874EDCAF7002CA98264193";
            HashOfOneToNine = "1886DB8ACDCBFEAB1E7EE3780400536F";
            HashOfSmallLettersAToE = "A0A954BE2A779BFB2129B72110C5782D";
            HashOfDefaultDataHMACWithShortKey = "BA844D13A1215E20634A49D5599197EF";
            HashOfDefaultDataHMACWithLongKey = "DD8988DF3CEC7610583CBB179DF63436";
        }
    }

    [TestFixture]
    internal class RIPEMD160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateRIPEMD160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "9C1185A5C5E9FC54612808977EE8F548B2258D31";
            HashOfDefaultData = "0B8EAC9A2EA1E267750CE639D83A84B92631462B";
            HashOfOneToNine = "D3D0379126C1E5E0BA70AD6E5E53FF6AEAB9F4FA";
            HashOfSmallLettersAToE = "973398B6E6C6CFA6B5E6A5173F195CE3274BF828";
            HashOfDefaultDataHMACWithShortKey = "76D728D9BF39ED42E0C451A9526E3F0D929F067D";
            HashOfDefaultDataHMACWithLongKey = "C317C69B2C1852B99B6FE321E25E6A2488774BF4";
        }
    }

    [TestFixture]
    internal class RIPEMD256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateRIPEMD256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "02BA4C4E5F8ECD1877FC52D64D30E37A2D9774FB1E5D026380AE0168E3C5522D";
            HashOfDefaultData = "95EF1FFAB0EF6229F58CAE347426ADE3C412BCEB1057DAED0062BBDEE4BEACC6";
            HashOfOneToNine = "6BE43FF65DD40EA4F2FF4AD58A7C1ACC7C8019137698945B16149EB95DF244B7";
            HashOfSmallLettersAToE = "81D8B58A3110A9139B4DDECCB031409E8AF023067CF4C6F0B701DAB9ECC0EB4E";
            HashOfDefaultDataHMACWithShortKey = "D59B820A708FA31C39BD33BA88CB9A25516A3BA2BA99A74223FCE0EC0F9BFB1B";
            HashOfDefaultDataHMACWithLongKey = "20AE8423C34565F32A9CCFDE5936D50DF0F9603F66CF6B3BAFD8E425301ABB6E";
        }
    }

    [TestFixture]
    internal class RIPEMD320Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateRIPEMD320();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "22D65D5661536CDC75C1FDF5C6DE7B41B9F27325EBC61E8557177D705A0EC880151C3A32A00899B8";
            HashOfDefaultData = "004A1899CCA02BFD4055129304D55F364E35F033BB74B784AFC93F7268291D8AF84F2C64C5CCACD0";
            HashOfOneToNine = "7E36771775A8D279475D4FD76B0C8E412B6AD085A0002475A148923CCFA5D71492E12FA88EEAF1A9";
            HashOfSmallLettersAToE = "A94DC1BC825DB64E97718305CE36BFEF32CC5410A630999678BCD89CC38C424269012EC8C5A95830";
            HashOfDefaultDataHMACWithShortKey =
                "4D3DFCCB43E5A60611A850C2141086CB16752505BA12E1B7953EA8859CB1E1DF3A698562A46DB41C";
            HashOfDefaultDataHMACWithLongKey =
                "97DD3B45D4E382F73BF42281E81E0CA99CB1C82FDAEAE30AC6637B36122863F82407C2A7DFE9FA05";
        }
    }

    [TestFixture]
    internal class SHA0Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA0();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "F96CEA198AD1DD5617AC084A3D92C6107708C0EF";
            HashOfDefaultData = "C9CBBE593DE122CA36B13CC37FE2CA8D5606FEED";
            HashOfOneToNine = "F0360779D2AF6615F306BB534223CF762A92E988";
            HashOfSmallLettersAToE = "D624E34951BB800F0ACAE773001DF8CFFE781BA8";
            HashOfDefaultDataHMACWithShortKey = "EAA73E85DCAC5BAD0A0E71C0695F901FC32DB38A";
            HashOfDefaultDataHMACWithLongKey = "3AD935BE61BBC3913312A27279EED889648E967F";
        }
    }

    [TestFixture]
    internal class SHA1Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA1();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
            HashOfDefaultData = "C8389876E94C043C47BA4BFF3D359884071DC310";
            HashOfOneToNine = "F7C3BC1D808E04732ADF679965CCC34CA7AE3441";
            HashOfSmallLettersAToE = "03DE6C570BFE24BFC328CCD7CA46B76EADAF4334";
            HashOfDefaultDataHMACWithShortKey = "CD409025AA5F34ABDC660856463155B23C89B16A";
            HashOfDefaultDataHMACWithLongKey = "956B4A490ECD0AE453D9927DABDCBC35E6E4BE51";
        }
    }

    [TestFixture]
    internal class SHA2_224Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA2_224();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
            HashOfDefaultData = "DF2B86ED008508F542443C4B1810AA5A0F5658692B808EEB1D0A2F7E";
            HashOfOneToNine = "9B3E61BF29F17C75572FAE2E86E17809A4513D07C8A18152ACF34521";
            HashOfSmallLettersAToE = "BDD03D560993E675516BA5A50638B6531AC2AC3D5847C61916CFCED6";
            HashOfDefaultDataHMACWithShortKey = "EC47E83DB5DD735EBB7AA4A898460950B16A3A0FA48E4BB9184EA3D1";
            HashOfDefaultDataHMACWithLongKey = "369B2FAF691265B647E13F7A46223816A93CF7885956C9855729D511";
        }
    }

    [TestFixture]
    internal class SHA2_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA2_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
            HashOfDefaultData = "BCF45544CB98DDAB731927F8760F81821489ED04C0792A4D254134887BEA9E38";
            HashOfOneToNine = "15E2B0D3C33891EBB0F1EF609EC419420C20E320CE94C65FBC8C3312448EB225";
            HashOfSmallLettersAToE = "36BBE50ED96841D10443BCB670D6554F0A34B761BE67EC9C4A8AD2C0C44CA42C";
            HashOfDefaultDataHMACWithShortKey = "92678A1C746AAEAA1D3F0C9DAC4BCA73801D278B51C1F6861D49C9A2C1175687";
            HashOfDefaultDataHMACWithLongKey = "91225F1256561F96A2636021545BBCFB1E241A2F88ACC36D2665D706AF1F67DC";
        }
    }

    [TestFixture]
    internal class SHA2_384Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA2_384();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B";
            HashOfDefaultData =
                "05D165ADA4A6F9F550CB6F9A0E00401E628B302FA5D7F3824361768758421F83102AC611B2710F5168579CFB11942869";
            HashOfOneToNine =
                "EB455D56D2C1A69DE64E832011F3393D45F3FA31D6842F21AF92D2FE469C499DA5E3179847334A18479C8D1DEDEA1BE3";
            HashOfSmallLettersAToE =
                "4C525CBEAC729EAF4B4665815BC5DB0C84FE6300068A727CF74E2813521565ABC0EC57A37EE4D8BE89D097C0D2AD52F0";
            HashOfDefaultDataHMACWithShortKey =
                "3D6DCED731DAF3599CC0971646C1A8B8CCC61650722F111A9EB26CE7B65189EB220EACB09152D9A09065099FE6C1FDC9";
            HashOfDefaultDataHMACWithLongKey =
                "AAB6B0697262C86C0088544B7D736F17C22F4B7EF5E3573B09CCADA94869335D1A6E2EC5D284AAD67E7CB0683730E031";
        }
    }

    [TestFixture]
    internal class SHA2_512Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA2_512();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E";
            HashOfDefaultData =
                "0A5DA12B113EBD3DEA4C51FD10AFECF1E2A8EE6C3848A0DD4407141ADDA04375068D85A1EEF980FAFF68DC3BF5B1B3FBA31344178042197B5180BD95530D61AC";
            HashOfOneToNine =
                "D9E6762DD1C8EAF6D61B3C6192FC408D4D6D5F1176D0C29169BC24E71C3F274AD27FCD5811B313D681F7E55EC02D73D499C95455B6B5BB503ACF574FBA8FFE85";
            HashOfSmallLettersAToE =
                "878AE65A92E86CAC011A570D4C30A7EAEC442B85CE8ECA0C2952B5E3CC0628C2E79D889AD4D5C7C626986D452DD86374B6FFAA7CD8B67665BEF2289A5C70B0A1";
            HashOfDefaultDataHMACWithShortKey =
                "DEDFCEAD40225068527D0E53B7C892226E188891D939E21A0777A40EA2E29D7233638C178C879F26088A502A887674C01DF61EAF1635D707D114097ED1D0D762";
            HashOfDefaultDataHMACWithLongKey =
                "18B5BEBCC175F7DC4CBE0D6808074F9EF88E1E655C09433D24C8B6FDB280D512D1DB34AE3BDA5DE127DA8C4C58EBF3C12B845253C98313A0134C117BB7A35452";
        }
    }

    [TestFixture]
    internal class SHA2_512_224Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA2_512_224();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4";
            HashOfDefaultData = "7A95749FB7F4489A45275556F5D905D28E1B637DCDD6537336AB6234";
            HashOfOneToNine = "F2A68A474BCBEA375E9FC62EAAB7B81FEFBDA64BB1C72D72E7C27314";
            HashOfSmallLettersAToE = "880E79BB0A1D2C9B7528D851EDB6B8342C58C831DE98123B432A4515";
            HashOfDefaultDataHMACWithShortKey = "9BC318A84B90F7FF55C53E3F4B602EAD13BB579EB1794455B29562B4";
            HashOfDefaultDataHMACWithLongKey = "90D4733F36AAACD0227DBBB1706DB44BB8F6900748A9DBA7544218A8";
        }
    }

    [TestFixture]
    internal class SHA2_512_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA2_512_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A";
            HashOfDefaultData = "E1792BAAAEBFC58E213D0BA628BF2FF22CBA10526075702F7C1727B76BEB107B";
            HashOfOneToNine = "1877345237853A31AD79E14C1FCB0DDCD3DF9973B61AF7F906E4B4D052CC9416";
            HashOfSmallLettersAToE = "DE8322B46E78B67D4431997070703E9764E03A1237B896FD8B379ED4576E8363";
            HashOfDefaultDataHMACWithShortKey = "1467239C9D47E1962905D03D7006170A04D05E4508BB47E30AD9481FBDA975FF";
            HashOfDefaultDataHMACWithLongKey = "E01FA9404415977D74ABB93622520176A216F633E26636D5EECD1E75BA30902A";
        }
    }

    [TestFixture]
    internal class SHA3_224Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA3_224();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7";
            HashOfDefaultData = "1D2BDFB95B0203C2BB7C739D813D69521EC7A3047E3FCA15CD305C95";
            HashOfOneToNine = "5795C3D628FD638C9835A4C79A55809F265068C88729A1A3FCDF8522";
            HashOfSmallLettersAToE = "6ACFAAB70AFD8439CEA3616B41088BD81C939B272548F6409CF30E57";
            HashOfDefaultDataHMACWithShortKey = "DA17722BA1E4BD728A83015A83430A67577F283A0EFCB457C327A980";
            HashOfDefaultDataHMACWithLongKey = "9D57F50CBE386534FED5C49F632AE18AB7A7C45D77FABD7222A84F35";
        }
    }

    [TestFixture]
    internal class SHA3_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA3_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A";
            HashOfDefaultData = "C334674D808EBB8B7C2926F043D1CAE78D168A05B70B9210C9167EA6DC300CE2";
            HashOfOneToNine = "87CD084D190E436F147322B90E7384F6A8E0676C99D21EF519EA718E51D45F9C";
            HashOfSmallLettersAToE = "D716EC61E18904A8F58679B71CB065D4D5DB72E0E0C3F155A4FEFF7ADD0E58EB";
            HashOfDefaultDataHMACWithShortKey = "1019B70021A038345192F00D02E33FA4AF8949E80AD592C4671A438DCCBCFBDF";
            HashOfDefaultDataHMACWithLongKey = "F48A2147119E3ADC96DD51021B717D98A61A3A74BD3781EB5C4EA6BAA70D997B";
        }
    }

    [TestFixture]
    internal class SHA3_384Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA3_384();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004";
            HashOfDefaultData =
                "87DD2935CD0DDEFFB8694E70ED1D33EABCEA848BD93A7A7B7227603B7C080A70BCF29FCEED66F456A7FB593EB23F950C";
            HashOfOneToNine =
                "8B90EDE4D095409F1A12492C2520599683A9478DC70B7566D23B3E41ECE8538C6CDE92382A5E38786490375C54672ABF";
            HashOfSmallLettersAToE =
                "348494236B82EDDA7602C78BA67FC3838E427C63C23E2C9D9AA5EA6354218A3C2CA564679ACABF3AC6BF5378047691C4";
            HashOfDefaultDataHMACWithShortKey =
                "52A4A926B60AA9F6B7DB1C8F5344A097540A8E2115164BF75734907E88C2BC1F7DD84D0EE8569B9857590A39EB5FF499";
            HashOfDefaultDataHMACWithLongKey =
                "BDBF2BD40E6DDD5EE093969879ACB44975BEA9E06922BD6C7494C0C85510D59D8B7CA0D17C74E23FF63DF97015F806C1";
        }
    }

    [TestFixture]
    internal class SHA3_512Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSHA3_512();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26";
            HashOfDefaultData =
                "FAA213B928B942C521FD2A4B5F918C9AB6479A1DD122B9485440E56E729976D57C5E7C62F65D8453DCAAADA6B79743DB939F22773FD44C9ECD54B4B7FAFDAE33";
            HashOfOneToNine =
                "E1E44D20556E97A180B6DD3ED7AE5C465CAFD553FA8747DCA038FB95635B77A37318F7DDF7AEC1F6C3C14BB160BA2497007DECF38DD361CAB199E3B8C8FE1F5C";
            HashOfSmallLettersAToE =
                "1D7C3AA6EE17DA5F4AEB78BE968AA38476DBEE54842E1AE2856F4C9A5CD04D45DC75C2902182B07C130ED582D476995B502B8777CCF69F60574471600386639B";
            HashOfDefaultDataHMACWithShortKey =
                "439C673B33F0F6D9273124782611EA96F1BB62F90672551310C1230ADAAD0D40F63C6D2B17DAFECEFD9CE8848576001D9D68FAD1B9E7DDC146F00CEBE5AFED27";
            HashOfDefaultDataHMACWithLongKey =
                "196FD60618333041460020DDAF61863C4AF5DA4FFE34FF08960F1F46368168A1716A769D0785DB42D547D3B089EF33B059C797D7E4BC61ECC5BB1717632510C1";
        }
    }

    [TestFixture]
    internal class Snefru_8_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSnefru_8_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "8617F366566A011837F4FB4BA5BEDEA2";
            HashOfDefaultData = "1EA32485C121D07D1BD22FC4EDCF554F";
            HashOfOneToNine = "486D27B1F5F4A20DEE14CC466EDA9069";
            HashOfSmallLettersAToE = "ADD78FA0BEA8F6283FE5D011BE6BCA3B";
            HashOfDefaultDataHMACWithShortKey = "B7D06604FCA943939525BA82BA69706E";
            HashOfDefaultDataHMACWithLongKey = "5E868C5B229D268962C1C8D3D594C90E";
        }
    }

    [TestFixture]
    internal class Snefru_8_256Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateSnefru_8_256();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "8617F366566A011837F4FB4BA5BEDEA2B892F3ED8B894023D16AE344B2BE5881";
            HashOfDefaultData = "230826DA59215F22AF36663491AECC4872F663722A5A7932428CB8196F7AF78D";
            HashOfOneToNine = "1C7DEDC33125AF7517970B97B635777FFBA8905D7A0B359776E3E683B115F992";
            HashOfSmallLettersAToE = "8D2891FC6020D7DC93F7561C0CFDDE26426192B3E364A1F52B634482009DC8C8";
            HashOfDefaultDataHMACWithShortKey = "7E33D94C5A09B2E5F800417128BCF3EF2EDCB971884789A35AE4AA7F13A18147";
            HashOfDefaultDataHMACWithLongKey = "CB966FF01AE3968FB5746298D2560F915BC2B8B006D50DF9EF91221B51DDCB01";
        }
    }

    [TestFixture]
    internal class Tiger_3_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_3_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "3293AC630C13F0245F92BBB1766E1616";
            HashOfDefaultData = "C76C85CE853F6E9858B507DA64E33DA2";
            HashOfOneToNine = "0672665140A491BB35040AA9943D769A";
            HashOfSmallLettersAToE = "BFD4041233531F1EF1E9A66D7A0CEF76";
            HashOfDefaultDataHMACWithShortKey = "0FA849F65841F2E621E2C882BE7CF80F";
            HashOfDefaultDataHMACWithLongKey = "4192C0318A673DBA30F14298B93A76E4";
        }
    }

    [TestFixture]
    internal class Tiger_4_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_4_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "24CC78A7F6FF3546E7984E59695CA13D";
            HashOfDefaultData = "42CAAEB3A7218E379A78E4F1F7FBADA4";
            HashOfOneToNine = "D9902D13011BD217DE965A3BA709F5CE";
            HashOfSmallLettersAToE = "7FD0E2FAEC50261EF48D3B87C554EE73";
            HashOfDefaultDataHMACWithShortKey = "856B697CEB606B1DF42B475D0C5587B5";
            HashOfDefaultDataHMACWithLongKey = "8B402D0B6531CC21712DD2DCF408747D";
        }
    }

    [TestFixture]
    internal class Tiger_5_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_5_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "E765EBE4C351724A1B99F96F2D7E62C9";
            HashOfDefaultData = "D6B8DCEA252160A4CBBF6A57DA9ABA78";
            HashOfOneToNine = "BCCCB6421B3EC291A062A33DFF21BA76";
            HashOfSmallLettersAToE = "1AB49D19F3C93B6FF4AB536951E5A6D0";
            HashOfDefaultDataHMACWithShortKey = "49D450EC293D5565CE82284FA52FDC51";
            HashOfDefaultDataHMACWithLongKey = "EFDCC5015260F7954F3F135A7188708D";
        }
    }

    internal class Tiger_3_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_3_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "3293AC630C13F0245F92BBB1766E16167A4E5849";
            HashOfDefaultData = "C76C85CE853F6E9858B507DA64E33DA27DE49F86";
            HashOfOneToNine = "0672665140A491BB35040AA9943D769A47BE83FE";
            HashOfSmallLettersAToE = "BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE75";
            HashOfDefaultDataHMACWithShortKey = "45AF6513756EB15B9504CE8212F3D43AE739E470";
            HashOfDefaultDataHMACWithLongKey = "35CCD0EEBAF187173D0C27BDFB8B8E4E14DC1758";
        }
    }

    internal class Tiger_4_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_4_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "24CC78A7F6FF3546E7984E59695CA13D804E0B68";
            HashOfDefaultData = "42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6";
            HashOfOneToNine = "D9902D13011BD217DE965A3BA709F5CE7E75ED2C";
            HashOfSmallLettersAToE = "7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98";
            HashOfDefaultDataHMACWithShortKey = "E8E8B8EF52CF7866A4E0AEAE7DE79878D5564997";
            HashOfDefaultDataHMACWithLongKey = "3AAE6E99155B53CA3F245EA88381ACC2B14E4713";
        }
    }

    internal class Tiger_5_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_5_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "E765EBE4C351724A1B99F96F2D7E62C9AACBE64C";
            HashOfDefaultData = "D6B8DCEA252160A4CBBF6A57DA9ABA78E4564864";
            HashOfOneToNine = "BCCCB6421B3EC291A062A33DFF21BA764596C58E";
            HashOfSmallLettersAToE = "1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C";
            HashOfDefaultDataHMACWithShortKey = "5F403B5F7F9A341545F55265698DD77DB8D3D6D4";
            HashOfDefaultDataHMACWithLongKey = "AD2D47B67DD7ACDB1CDEBBD8E7F47DA6F42634C2";
        }
    }

    internal class Tiger_3_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_3_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3";
            HashOfDefaultData = "C76C85CE853F6E9858B507DA64E33DA27DE49F8601F6A830";
            HashOfOneToNine = "0672665140A491BB35040AA9943D769A47BE83FEF2126E50";
            HashOfSmallLettersAToE = "BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE756B36A7D7";
            HashOfDefaultDataHMACWithShortKey = "9B53DDED2647666E9C31CF0F93B3B83E9FF64DF4532F3DDC";
            HashOfDefaultDataHMACWithLongKey = "1CF2C7D3B653E2A68AA11FBBC7472DFC8F4ABE3FA51C09FB";
        }
    }

    internal class Tiger_4_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_4_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "24CC78A7F6FF3546E7984E59695CA13D804E0B686E255194";
            HashOfDefaultData = "42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6A41827B0";
            HashOfOneToNine = "D9902D13011BD217DE965A3BA709F5CE7E75ED2CB791FEA6";
            HashOfSmallLettersAToE = "7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98F9A0B332";
            HashOfDefaultDataHMACWithShortKey = "D1113A9110545D0F3C97BE1451A8FAED205B1F27B3D74560";
            HashOfDefaultDataHMACWithLongKey = "E85EC91A39ED382A13B26F6F6C8DD80573104AF4CF93712B";
        }
    }

    internal class Tiger_5_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger_5_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "E765EBE4C351724A1B99F96F2D7E62C9AACBE64C63B5BCA2";
            HashOfDefaultData = "D6B8DCEA252160A4CBBF6A57DA9ABA78E45648645715E3CE";
            HashOfOneToNine = "BCCCB6421B3EC291A062A33DFF21BA764596C58E30854A92";
            HashOfSmallLettersAToE = "1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C3471A08F";
            HashOfDefaultDataHMACWithShortKey = "8D56E7164C246EAF4708AAEECFE4DD439F5B4396A54049A6";
            HashOfDefaultDataHMACWithLongKey = "4927ABD344D9A9EAE65EA88E03A0E5F37BFDEC8C457D64B3";
        }
    }

    [TestFixture]
    internal class Tiger2_3_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_3_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "4441BE75F6018773C206C22745374B92";
            HashOfDefaultData = "DEB1924D290E3D5567792A8171BFC44F";
            HashOfOneToNine = "82FAF69673762B9FD8A0C902BDB395C1";
            HashOfSmallLettersAToE = "E1F0DAC9E852ECF1270FB691C35506D4";
            HashOfDefaultDataHMACWithShortKey = "0393C69DD393D9E15C723DFAE88C3059";
            HashOfDefaultDataHMACWithLongKey = "610CA106E5C500E6E073C337D6CF9C63";
        }
    }

    [TestFixture]
    internal class Tiger2_4_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_4_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "6A7201A47AAC2065913811175553489A";
            HashOfDefaultData = "22EE5BFE174B8C1C23361306C3E8F32C";
            HashOfOneToNine = "75B7D71ACD40FE5B5D3263C1F68F4CF5";
            HashOfSmallLettersAToE = "9FBB0FBF818C0302890CE373559D2370";
            HashOfDefaultDataHMACWithShortKey = "A24C1DD76CACA54D3CB2BDDE5E40D84E";
            HashOfDefaultDataHMACWithLongKey = "0113ECE2E287D9DBD0AC836968F56E70";
        }
    }

    [TestFixture]
    internal class Tiger2_5_128Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_5_128();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "61C657CC0C3C147ED90779B36A1E811F";
            HashOfDefaultData = "7F71F95B346733E7022D4B85BDA9C51E";
            HashOfOneToNine = "F720446C9BFDC8479D9FA53BC8B9144F";
            HashOfSmallLettersAToE = "14F45FAC4BE0302E740CCC6FE99D75A6";
            HashOfDefaultDataHMACWithShortKey = "F545BB88FBE3E5FB85E6DE063D081B66";
            HashOfDefaultDataHMACWithLongKey = "7D5547482639AE44E3CA6E16AEEE118A";
        }
    }

    internal class Tiger2_3_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_3_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "4441BE75F6018773C206C22745374B924AA8313F";
            HashOfDefaultData = "DEB1924D290E3D5567792A8171BFC44F70B5CD13";
            HashOfOneToNine = "82FAF69673762B9FD8A0C902BDB395C12B0CBDDC";
            HashOfSmallLettersAToE = "E1F0DAC9E852ECF1270FB691C35506D4BEDB12A0";
            HashOfDefaultDataHMACWithShortKey = "71028DCDC197492195110EA5CFF6B3E04912FF25";
            HashOfDefaultDataHMACWithLongKey = "A8CC78CCD014F6A08AF1267E12D05FA472904E4D";
        }
    }

    internal class Tiger2_4_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_4_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "6A7201A47AAC2065913811175553489ADD0F8B99";
            HashOfDefaultData = "22EE5BFE174B8C1C23361306C3E8F32C92075577";
            HashOfOneToNine = "75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B";
            HashOfSmallLettersAToE = "9FBB0FBF818C0302890CE373559D23702D87C69B";
            HashOfDefaultDataHMACWithShortKey = "283A6ED11043AAA947A12843DC5C4B16283BE633";
            HashOfDefaultDataHMACWithLongKey = "C5EC439F91CC537CCF013E33F88ABCBCC05AE365";
        }
    }

    internal class Tiger2_5_160Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_5_160();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "61C657CC0C3C147ED90779B36A1E811F1D27F406";
            HashOfDefaultData = "7F71F95B346733E7022D4B85BDA9C51E904825F7";
            HashOfOneToNine = "F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED";
            HashOfSmallLettersAToE = "14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177";
            HashOfDefaultDataHMACWithShortKey = "DDEE30DCE9CD2A11C38ADA8AC94FD5BD90EC1BA4";
            HashOfDefaultDataHMACWithLongKey = "84A10F68F3826DA059CDD107D84931E7623C7E67";
        }
    }

    internal class Tiger2_3_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_3_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "4441BE75F6018773C206C22745374B924AA8313FEF919F41";
            HashOfDefaultData = "DEB1924D290E3D5567792A8171BFC44F70B5CD13480D6D5C";
            HashOfOneToNine = "82FAF69673762B9FD8A0C902BDB395C12B0CBDDC66957838";
            HashOfSmallLettersAToE = "E1F0DAC9E852ECF1270FB691C35506D4BEDB12A09D6BF911";
            HashOfDefaultDataHMACWithShortKey = "C70FA522EACE7D870F914A086BD1D9807A6FDC405C5A09DB";
            HashOfDefaultDataHMACWithLongKey = "AB8648339AF3C379C16E3595539E787A3464E7BB30810F2A";
        }
    }

    internal class Tiger2_4_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_4_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "6A7201A47AAC2065913811175553489ADD0F8B99E65A0955";
            HashOfDefaultData = "22EE5BFE174B8C1C23361306C3E8F32C92075577F9115C2A";
            HashOfOneToNine = "75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B39413ACA";
            HashOfSmallLettersAToE = "9FBB0FBF818C0302890CE373559D23702D87C69B9D1B29D5";
            HashOfDefaultDataHMACWithShortKey = "3B182344C171E8843B3D30887274FC7248A7CCD49AA84E77";
            HashOfDefaultDataHMACWithLongKey = "EE9F8B721F29C5085FF542F170ED9AF33B0D58229632E248";
        }
    }

    internal class Tiger2_5_192Test : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateTiger2_5_192();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData = "61C657CC0C3C147ED90779B36A1E811F1D27F406E3F37010";
            HashOfDefaultData = "7F71F95B346733E7022D4B85BDA9C51E904825F73AF0E8AE";
            HashOfOneToNine = "F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED1440C213";
            HashOfSmallLettersAToE = "14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177B4ADF2A8";
            HashOfDefaultDataHMACWithShortKey = "19AD11BA8D3534C41CAA2A9DAA80958EDCDB0B67FF3BF55D";
            HashOfDefaultDataHMACWithLongKey = "0DEC75166CD4CFF2A564373827255CDAF7A278CCF2143ED4";
        }
    }

    internal class WhirlPoolTest : CryptoAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Crypto.CreateWhirlPool();
            HMACInstance = HashFactory.HMAC.CreateHMAC(HashInstance, ZeroByteArray);
            HashOfEmptyData =
                "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3";
            HashOfDefaultData =
                "9D2BB47D6F6D9F0DBAF08BEF416DE06C98CDF293F3D1AD2422A63A9ADFBD9AA33F888A1C6FE7C16DF33B2BD9FFD8EF160BCF6AB4F21B682DC238A3BE03AB0F12";
            HashOfOneToNine =
                "21D5CB651222C347EA1284C0ACF162000B4D3E34766F0D00312E3480F633088822809B6A54BA7EDFA17E8FCB5713F8912EE3A218DD98D88C38BBF611B1B1ED2B";
            HashOfSmallLettersAToE =
                "5D745E26CCB20FE655D39C9E7F69455758FBAE541CB892B3581E4869244AB35B4FD6078F5D28B1F1A217452A67D9801033D92724A221255A5E377FE9E9E5F0B2";
            HashOfDefaultDataHMACWithShortKey =
                "72B3CFC10CC32F9203670984407594B9F2A6C9F1A46C3FF7DF76AD07207758F96CF46C448A7687EBBA5EBC046984B4837320306EB27978A58B8CF447978CADEA";
            HashOfDefaultDataHMACWithLongKey =
                "AD41F88A4777E33A0D128B231A6C723417C3533E0106B916B4AEED4AA954CBB000B99714AA6462D6691F426523341FE0EAAEB4D277A3E911B2BA22E33081B500";
        }
    }
}