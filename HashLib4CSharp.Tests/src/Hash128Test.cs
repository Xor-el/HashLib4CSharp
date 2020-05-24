using HashLib4CSharp.Base;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    internal class MurmurHash3_x86_128Test : FourByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash128.CreateMurmurHash3_x86_128();
            HashOfEmptyData = "00000000000000000000000000000000";
            HashOfDefaultData = "B35E1058738E067BF637B17075F14B8B";
            HashOfOneToNine = "C65876BB119A1552C5E3E5D7A9168CA4";
            HashOfSmallLettersAToE = "C5402EFB5D24C5BC5A7201775A720177";
            HashOfDefaultDataWithFourByteKey = "55315FA9E8129C7390C080B8FDB1C972";
        }
    }

    internal class MurmurHash3_x64_128Test : FourByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash128.CreateMurmurHash3_x64_128();
            HashOfEmptyData = "00000000000000000000000000000000";
            HashOfDefaultData = "705BD3C954B94BE056F06B68662E6364";
            HashOfOneToNine = "3C84645EDB66CCA499F8FAC73A1EA105";
            HashOfSmallLettersAToE = "2036D091F496BBB8C5C7EEA04BCFEC8C";
            HashOfDefaultDataWithFourByteKey = "ADFD14988FB1F8582A1B67C1BBACC218";
        }
    }

    internal class SipHash128_2_4Test : SixteenByteKeyAlgorithmTestBase
    {
        [OneTimeSetUp]
        public void Setup()
        {
            HashInstance = HashFactory.Hash128.CreateSipHash128_2_4();
            HashOfEmptyData = "A3817F04BA25A8E66DF67214C7550293";
            HashOfDefaultData = "312C82F65D5A567B333CD772F045E36C";
            HashOfOneToNine = "CE94828373303D1AB5FC781744AD71CE";
            HashOfSmallLettersAToE = "EB8662A95F0D718811E7CEDBDF03541C";
            HashOfDefaultDataWithSixteenByteKey = "312C82F65D5A567B333CD772F045E36C";
        }
    }
}