/*
HashLib4CSharp Library
Copyright (c) 2020 Ugochukwu Mmaduekwe
GitHub Profile URL <https://github.com/Xor-el>

Distributed under the MIT software license, see the accompanying LICENSE file
or visit http://www.opensource.org/licenses/mit-license.php.

Acknowledgements:
This library was sponsored by Sphere 10 Software (https://www.sphere10.com)
for the purposes of supporting the XXX (https://YYY) project.
*/

using System;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class Grindahl512 : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private static readonly ulong[] Table0 = new ulong[256];
        private static readonly ulong[] Table1 = new ulong[256];
        private static readonly ulong[] Table2 = new ulong[256];
        private static readonly ulong[] Table3 = new ulong[256];
        private static readonly ulong[] Table4 = new ulong[256];
        private static readonly ulong[] Table5 = new ulong[256];
        private static readonly ulong[] Table6 = new ulong[256];
        private static readonly ulong[] Table7 = new ulong[256];

        private static readonly ulong[] MasterTable =
        {
            0xC6636397633551A2,
            0xF87C7CEB7CCD1326, 0xEE7777C777952952,
            0xF67B7BF77BF50102, 0xFFF2F2E5F2D11A34,
            0xD66B6BB76B7561C2, 0xDE6F6FA76F5579F2,
            0x91C5C539C572A84B, 0x603030C0309BA05B,
            0x020101040108060C, 0xCE67678767154992,
            0x562B2BAC2B43FAEF, 0xE7FEFED5FEB13264,
            0xB5D7D771D7E2C493, 0x4DABAB9AAB2FD7B5,
            0xEC7676C3769D2F5E, 0x8FCACA05CA0A8A0F,
            0x1F82823E827C2142, 0x89C9C909C912801B,
            0xFA7D7DEF7DC5152A, 0xEFFAFAC5FA912A54,
            0xB259597F59FECD81, 0x8E474707470E8909,
            0xFBF0F0EDF0C1162C, 0x41ADAD82AD1FC39D,
            0xB3D4D47DD4FACE87, 0x5FA2A2BEA267E1D9,
            0x45AFAF8AAF0FCF85, 0x239C9C469C8C65CA,
            0x53A4A4A6A457F5F1, 0xE47272D372BD376E,
            0x9BC0C02DC05AB677, 0x75B7B7EAB7CF9F25,
            0xE1FDFDD9FDA93870, 0x3D93937A93F4478E,
            0x4C262698262BD4B3, 0x6C3636D836ABB473,
            0x7E3F3FFC3FE3821F, 0xF5F7F7F1F7F90408,
            0x83CCCC1DCC3A9E27, 0x683434D034BBB86B,
            0x51A5A5A2A55FF3FD, 0xD1E5E5B9E56968D0,
            0xF9F1F1E9F1C91020, 0xE27171DF71A53D7A,
            0xABD8D84DD89AE6D7, 0x623131C43193A657,
            0x2A15155415A87EFC, 0x0804041004201830,
            0x95C7C731C762A453, 0x4623238C2303CA8F,
            0x9DC3C321C342BC63, 0x3018186018C050A0,
            0x3796966E96DC59B2, 0x0A05051405281E3C,
            0x2F9A9A5E9ABC71E2, 0x0E07071C07381224,
            0x2412124812906CD8, 0x1B808036806C2D5A,
            0xDFE2E2A5E2517AF4, 0xCDEBEB81EB194C98,
            0x4E27279C2723D2BF, 0x7FB2B2FEB2E78119,
            0xEA7575CF7585254A, 0x120909240948366C,
            0x1D83833A8374274E, 0x582C2CB02C7BE8CB,
            0x341A1A681AD05CB8, 0x361B1B6C1BD85AB4,
            0xDC6E6EA36E5D7FFE, 0xB45A5A735AE6C795,
            0x5BA0A0B6A077EDC1, 0xA452525352A6F7F5,
            0x763B3BEC3BC39A2F, 0xB7D6D675D6EAC29F,
            0x7DB3B3FAB3EF8715, 0x522929A42953F6F7,
            0xDDE3E3A1E3597CF8, 0x5E2F2FBC2F63E2DF,
            0x13848426844C356A, 0xA653535753AEF1F9,
            0xB9D1D169D1D2D0BB, 0x0000000000000000,
            0xC1EDED99ED2958B0, 0x40202080201BC09B,
            0xE3FCFCDDFCA13E7C, 0x79B1B1F2B1FF8B0D,
            0xB65B5B775BEEC199, 0xD46A6AB36A7D67CE,
            0x8DCBCB01CB028C03, 0x67BEBECEBE87A949,
            0x723939E439D39637, 0x944A4A334A66A755,
            0x984C4C2B4C56B37D, 0xB058587B58F6CB8D,
            0x85CFCF11CF229433, 0xBBD0D06DD0DAD6B7,
            0xC5EFEF91EF3954A8, 0x4FAAAA9EAA27D1B9,
            0xEDFBFBC1FB992C58, 0x86434317432E9139,
            0x9A4D4D2F4D5EB571, 0x663333CC3383AA4F,
            0x1185852285443366, 0x8A45450F451E8511,
            0xE9F9F9C9F9892040, 0x0402020802100C18,
            0xFE7F7FE77FD51932, 0xA050505B50B6FBED,
            0x783C3CF03CFB880B, 0x259F9F4A9F946FDE,
            0x4BA8A896A837DDA1, 0xA251515F51BEFDE1,
            0x5DA3A3BAA36FE7D5, 0x8040401B40369B2D,
            0x058F8F0A8F140F1E, 0x3F92927E92FC4182,
            0x219D9D429D8463C6, 0x703838E038DB903B,
            0xF1F5F5F9F5E90810, 0x63BCBCC6BC97A551,
            0x77B6B6EEB6C79929, 0xAFDADA45DA8AEACF,
            0x422121842113C697, 0x20101040108060C0,
            0xE5FFFFD1FFB93468, 0xFDF3F3E1F3D91C38,
            0xBFD2D265D2CADAAF, 0x81CDCD19CD32982B,
            0x180C0C300C602850, 0x2613134C13986AD4,
            0xC3ECEC9DEC215EBC, 0xBE5F5F675FCED9A9,
            0x3597976A97D45FBE, 0x8844440B4416831D,
            0x2E17175C17B872E4, 0x93C4C43DC47AAE47,
            0x55A7A7AAA74FFFE5, 0xFC7E7EE37EDD1F3E,
            0x7A3D3DF43DF38E07, 0xC864648B640D4386,
            0xBA5D5D6F5DDED5B1, 0x3219196419C856AC,
            0xE67373D773B53162, 0xC060609B602D5BB6,
            0x1981813281642B56, 0x9E4F4F274F4EB969,
            0xA3DCDC5DDCBAFEE7, 0x44222288220BCC83,
            0x542A2AA82A4BFCE3, 0x3B90907690EC4D9A,
            0x0B888816882C1D3A, 0x8C46460346068F05,
            0xC7EEEE95EE3152A4, 0x6BB8B8D6B8B7BD61,
            0x2814145014A078F0, 0xA7DEDE55DEAAF2FF,
            0xBC5E5E635EC6DFA5, 0x160B0B2C0B583A74,
            0xADDBDB41DB82ECC3, 0xDBE0E0ADE04176EC,
            0x643232C8328BAC43, 0x743A3AE83ACB9C23,
            0x140A0A280A503C78, 0x9249493F497EAD41,
            0x0C06061806301428, 0x48242490243BD8AB,
            0xB85C5C6B5CD6D3BD, 0x9FC2C225C24ABA6F,
            0xBDD3D361D3C2DCA3, 0x43ACAC86AC17C591,
            0xC4626293623D57AE, 0x3991917291E44B96,
            0x3195956295C453A6, 0xD3E4E4BDE4616EDC,
            0xF27979FF79E50D1A, 0xD5E7E7B1E77964C8,
            0x8BC8C80DC81A8617, 0x6E3737DC37A3B27F,
            0xDA6D6DAF6D4575EA, 0x018D8D028D040306,
            0xB1D5D579D5F2C88B, 0x9C4E4E234E46BF65,
            0x49A9A992A93FDBAD, 0xD86C6CAB6C4D73E6,
            0xAC5656435686EFC5, 0xF3F4F4FDF4E10E1C,
            0xCFEAEA85EA114A94, 0xCA65658F6505458A,
            0xF47A7AF37AFD070E, 0x47AEAE8EAE07C989,
            0x1008082008403060, 0x6FBABADEBAA7B179,
            0xF07878FB78ED0B16, 0x4A2525942533DEA7,
            0x5C2E2EB82E6BE4D3, 0x381C1C701CE04890,
            0x57A6A6AEA647F9E9, 0x73B4B4E6B4D79531,
            0x97C6C635C66AA25F, 0xCBE8E88DE801468C,
            0xA1DDDD59DDB2F8EB, 0xE87474CB748D2346,
            0x3E1F1F7C1FF84284, 0x964B4B374B6EA159,
            0x61BDBDC2BD9FA35D, 0x0D8B8B1A8B34172E,
            0x0F8A8A1E8A3C1122, 0xE07070DB70AD3B76,
            0x7C3E3EF83EEB8413, 0x71B5B5E2B5DF933D,
            0xCC666683661D4F9E, 0x9048483B4876AB4D,
            0x0603030C03180A14, 0xF7F6F6F5F6F10204,
            0x1C0E0E380E702448, 0xC261619F61255DBA,
            0x6A3535D435B3BE67, 0xAE575747578EE9C9,
            0x69B9B9D2B9BFBB6D, 0x1786862E865C3972,
            0x99C1C129C152B07B, 0x3A1D1D741DE84E9C,
            0x279E9E4E9E9C69D2, 0xD9E1E1A9E14970E0,
            0xEBF8F8CDF881264C, 0x2B98985698AC7DFA,
            0x22111144118866CC, 0xD26969BF69656DDA,
            0xA9D9D949D992E0DB, 0x078E8E0E8E1C0912,
            0x3394946694CC55AA, 0x2D9B9B5A9BB477EE,
            0x3C1E1E781EF04488, 0x1587872A87543F7E,
            0xC9E9E989E9094080, 0x87CECE15CE2A923F,
            0xAA55554F559EE5D1, 0x502828A0285BF0FB,
            0xA5DFDF51DFA2F4F3, 0x038C8C068C0C050A,
            0x59A1A1B2A17FEBCD, 0x0989891289241B36,
            0x1A0D0D340D682E5C, 0x65BFBFCABF8FAF45,
            0xD7E6E6B5E67162C4, 0x8442421342269735,
            0xD06868BB686D6BD6, 0x8241411F413E9D21,
            0x2999995299A47BF6, 0x5A2D2DB42D73EEC7,
            0x1E0F0F3C0F782244, 0x7BB0B0F6B0F78D01,
            0xA854544B5496E3DD, 0x6DBBBBDABBAFB775,
            0x2C16165816B074E8
        };

        private ulong[] _state;
        private ulong[] _temp;

        static unsafe Grindahl512()
        {
            fixed (ulong* ptrTable0 = Table0, ptrTable1 = Table1, ptrTable2 = Table2,
                ptrTable3 = Table3, ptrTable4 = Table4, ptrTable5 = Table5, ptrTable6 = Table6,
                ptrTable7 = Table7, ptrMasterTable = MasterTable)
            {
                PointerUtils.MemMove(ptrTable0, ptrMasterTable, MasterTable.Length * sizeof(ulong));


                CalcTable(1, ptrTable1);
                CalcTable(2, ptrTable2);
                CalcTable(3, ptrTable3);
                CalcTable(4, ptrTable4);
                CalcTable(5, ptrTable5);
                CalcTable(6, ptrTable6);
                CalcTable(7, ptrTable7);
            }
        }

        internal Grindahl512()
            : base(64, 8)
        {
            _state = new ulong[13];
            _temp = new ulong[13];
        }

        public override IHash Clone() =>
            new Grindahl512
            {
                _state = ArrayUtils.Clone(_state),
                _temp = ArrayUtils.Clone(_temp),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            ArrayUtils.ZeroFill(_state);
            ArrayUtils.ZeroFill(_temp);

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (ulong* statePtr = &_state[5])
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.be64_copy(statePtr, 0, resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        }

        protected override unsafe void Finish()
        {
            var paddingSize = 16 - (int) (ProcessedBytesCount & 7);
            var msgLength = (ProcessedBytesCount >> 3) + 1;

            Span<byte> pad = stackalloc byte[paddingSize];

            pad[0] = 0x80;

            msgLength = Converters.be2me_64(msgLength);

            Converters.ReadUInt64AsBytesLE(msgLength, pad.Slice( paddingSize - 8));

            TransformByteSpan(pad.Slice( 0, paddingSize - 8));

            fixed (byte* ptrPad = pad)
            {
                _state[0] = Converters.ReadBytesAsUInt64LE(ptrPad, paddingSize - 8);
                _state[0] = Converters.be2me_64(_state[0]);
            }

            InjectMsg(true);

            for (var i = 0; i < 8; i++) InjectMsg(true);
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            _state[0] = Converters.ReadBytesAsUInt64LE((byte*) data, index);

            _state[0] = Converters.be2me_64(_state[0]);

            InjectMsg(false);
        }

        private static unsafe void CalcTable(int i, ulong* result)
        {
            for (var j = 0; j < 256; j++) result[j] = Bits.RotateRight64(MasterTable[j], i * 8);
        }

        private void InjectMsg(bool fullProcess)
        {
            _state[12] = _state[12] ^ 0x01;

            if (fullProcess)
                _temp[0] = Table0[(byte) (_state[12] >> 56)] ^ Table1
                    [(byte) (_state[11] >> 48)] ^ Table2[(byte) (_state[10] >> 40)
                ] ^ Table3[(byte) (_state[9] >> 32)] ^ Table4
                    [(byte) (_state[8] >> 24)] ^ Table5[(byte) (_state[7] >> 16)
                ] ^ Table6[(byte) (_state[6] >> 8)] ^ Table7
                    [(byte) _state[5]];

            _temp[1] = Table0[(byte) (_state[0] >> 56)] ^ Table1
                [(byte) (_state[12] >> 48)] ^ Table2[(byte) (_state[11] >> 40)
            ] ^ Table3[(byte) (_state[10] >> 32)] ^ Table4
                [(byte) (_state[9] >> 24)] ^ Table5[(byte) (_state[8] >> 16)
            ] ^ Table6[(byte) (_state[7] >> 8)] ^ Table7[(byte) _state[6]];

            _temp[2] = Table0[(byte) (_state[1] >> 56)] ^ Table1
                [(byte) (_state[0] >> 48)] ^ Table2[(byte) (_state[12] >> 40)
            ] ^ Table3[(byte) (_state[11] >> 32)] ^ Table4
                [(byte) (_state[10] >> 24)] ^ Table5[(byte) (_state[9] >> 16)
            ] ^ Table6[(byte) (_state[8] >> 8)] ^ Table7[(byte) _state[7]];

            _temp[3] = Table0[(byte) (_state[2] >> 56)] ^ Table1
                [(byte) (_state[1] >> 48)] ^ Table2[(byte) (_state[0] >> 40)
            ] ^ Table3[(byte) (_state[12] >> 32)] ^ Table4
                [(byte) (_state[11] >> 24)] ^ Table5[(byte) (_state[10] >> 16)
            ] ^ Table6[(byte) (_state[9] >> 8)] ^ Table7[(byte) _state[8]];

            _temp[4] = Table0[(byte) (_state[3] >> 56)] ^ Table1
                [(byte) (_state[2] >> 48)] ^ Table2[(byte) (_state[1] >> 40)
            ] ^ Table3[(byte) (_state[0] >> 32)] ^ Table4
                [(byte) (_state[12] >> 24)] ^ Table5[(byte) (_state[11] >> 16)
            ] ^ Table6[(byte) (_state[10] >> 8)] ^ Table7
                [(byte) _state[9]];

            _temp[5] = Table0[(byte) (_state[4] >> 56)] ^ Table1
                [(byte) (_state[3] >> 48)] ^ Table2[(byte) (_state[2] >> 40)
            ] ^ Table3[(byte) (_state[1] >> 32)] ^ Table4
                [(byte) (_state[0] >> 24)] ^ Table5[(byte) (_state[12] >> 16)
            ] ^ Table6[(byte) (_state[11] >> 8)] ^ Table7
                [(byte) _state[10]];

            _temp[6] = Table0[(byte) (_state[5] >> 56)] ^ Table1
                [(byte) (_state[4] >> 48)] ^ Table2[(byte) (_state[3] >> 40)
            ] ^ Table3[(byte) (_state[2] >> 32)] ^ Table4
                [(byte) (_state[1] >> 24)] ^ Table5[(byte) (_state[0] >> 16)
            ] ^ Table6[(byte) (_state[12] >> 8)] ^ Table7
                [(byte) _state[11]];

            _temp[7] = Table0[(byte) (_state[6] >> 56)] ^ Table1
                [(byte) (_state[5] >> 48)] ^ Table2[(byte) (_state[4] >> 40)
            ] ^ Table3[(byte) (_state[3] >> 32)] ^ Table4
                [(byte) (_state[2] >> 24)] ^ Table5[(byte) (_state[1] >> 16)
            ] ^ Table6[(byte) (_state[0] >> 8)] ^ Table7
                [(byte) _state[12]];

            _temp[8] = Table0[(byte) (_state[7] >> 56)] ^ Table1
                [(byte) (_state[6] >> 48)] ^ Table2[(byte) (_state[5] >> 40)
            ] ^ Table3[(byte) (_state[4] >> 32)] ^ Table4
                [(byte) (_state[3] >> 24)] ^ Table5[(byte) (_state[2] >> 16)
            ] ^ Table6[(byte) (_state[1] >> 8)] ^ Table7[(byte) _state[0]];

            _temp[9] = Table0[(byte) (_state[8] >> 56)] ^ Table1
                [(byte) (_state[7] >> 48)] ^ Table2[(byte) (_state[6] >> 40)
            ] ^ Table3[(byte) (_state[5] >> 32)] ^ Table4
                [(byte) (_state[4] >> 24)] ^ Table5[(byte) (_state[3] >> 16)
            ] ^ Table6[(byte) (_state[2] >> 8)] ^ Table7[(byte) _state[1]];

            _temp[10] = Table0[(byte) (_state[9] >> 56)] ^ Table1
                [(byte) (_state[8] >> 48)] ^ Table2[(byte) (_state[7] >> 40)
            ] ^ Table3[(byte) (_state[6] >> 32)] ^ Table4
                [(byte) (_state[5] >> 24)] ^ Table5[(byte) (_state[4] >> 16)
            ] ^ Table6[(byte) (_state[3] >> 8)] ^ Table7[(byte) _state[2]];

            _temp[11] = Table0[(byte) (_state[10] >> 56)] ^ Table1
                [(byte) (_state[9] >> 48)] ^ Table2[(byte) (_state[8] >> 40)
            ] ^ Table3[(byte) (_state[7] >> 32)] ^ Table4
                [(byte) (_state[6] >> 24)] ^ Table5[(byte) (_state[5] >> 16)
            ] ^ Table6[(byte) (_state[4] >> 8)] ^ Table7[(byte) _state[3]];

            _temp[12] = Table0[(byte) (_state[11] >> 56)] ^ Table1
                [(byte) (_state[10] >> 48)] ^ Table2[(byte) (_state[9] >> 40)
            ] ^ Table3[(byte) (_state[8] >> 32)] ^ Table4
                [(byte) (_state[7] >> 24)] ^ Table5[(byte) (_state[6] >> 16)
            ] ^ Table6[(byte) (_state[5] >> 8)] ^ Table7[(byte) _state[4]];

            // Swap memory pointers
            var t = _temp;
            _temp = _state;
            _state = t;
        }
    }
}