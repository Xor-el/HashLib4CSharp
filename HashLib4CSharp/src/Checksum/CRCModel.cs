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

using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Checksum
{
    public sealed class CRCModel
    {
        public int Width { get; set; }

        public ulong Polynomial { get; set; }

        public ulong InitialValue { get; set; }

        public bool ReflectIn { get; set; }

        public bool ReflectOut { get; set; }

        public ulong XorOut { get; set; }

        public ulong CheckValue { get; set; }

        public string[] Names { get; set; }

        public CRCModel Clone() =>
            new CRCModel
            {
                Width = Width,
                Polynomial = Polynomial,
                InitialValue = InitialValue,
                ReflectIn = ReflectIn,
                ReflectOut = ReflectOut,
                XorOut = XorOut,
                CheckValue = CheckValue,
                Names = ArrayUtils.Clone(Names)
            };

// A vast majority if not all of the parameters for these CRC standards
// were gotten from http://reveng.sourceforge.net/crc-catalogue/.

        public static CRCModel CRC3_GSM => new CRCModel
        {
            Width = 3,
            Polynomial = 0x3,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x7,
            CheckValue = 0x4,
            Names = new[] {"CRC-3/GSM"}
        };

        public static CRCModel CRC3_ROHC => new CRCModel
        {
            Width = 3,
            Polynomial = 0x3,
            InitialValue = 0x7,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x6,
            Names = new[] {"CRC-3/ROHC"}
        };

        public static CRCModel CRC4_INTERLAKEN => new CRCModel
        {
            Width = 4,
            Polynomial = 0x3,
            InitialValue = 0xF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xF,
            CheckValue = 0xB,
            Names = new[] {"CRC-4/INTERLAKEN"}
        };

        public static CRCModel CRC4_ITU => new CRCModel
        {
            Width = 4,
            Polynomial = 0x3,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x7,
            Names = new[] {"CRC-4/ITU", "CRC-4/G-704"}
        };

        public static CRCModel CRC5_EPC => new CRCModel
        {
            Width = 5,
            Polynomial = 0x9,
            InitialValue = 0x9,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x0,
            Names = new[] {"CRC-5/EPC", "CRC-5/EPC-C1G2"}
        };

        public static CRCModel CRC5_ITU => new CRCModel
        {
            Width = 5,
            Polynomial = 0x15,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x7,
            Names = new[] {"CRC-5/ITU", "CRC-5/G-704"}
        };

        public static CRCModel CRC5_USB => new CRCModel
        {
            Width = 5,
            Polynomial = 0x5,
            InitialValue = 0x1F,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x1F,
            CheckValue = 0x19,
            Names = new[] {"CRC-5/USB"}
        };

        public static CRCModel CRC6_CDMA2000A => new CRCModel
        {
            Width = 6,
            Polynomial = 0x27,
            InitialValue = 0x3F,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xD,
            Names = new[] {"CRC-6/CDMA2000-A"}
        };

        public static CRCModel CRC6_CDMA2000B => new CRCModel
        {
            Width = 6,
            Polynomial = 0x7,
            InitialValue = 0x3F,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x3B,
            Names = new[] {"CRC-6/CDMA2000-B"}
        };

        public static CRCModel CRC6_DARC => new CRCModel
        {
            Width = 6,
            Polynomial = 0x19,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x26,
            Names = new[] {"CRC-6/DARC"}
        };

        public static CRCModel CRC6_GSM => new CRCModel
        {
            Width = 6,
            Polynomial = 0x2F,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x3F,
            CheckValue = 0x13,
            Names = new[] {"CRC-6/GSM"}
        };

        public static CRCModel CRC6_ITU => new CRCModel
        {
            Width = 6,
            Polynomial = 0x3,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x6,
            Names = new[] {"CRC-6/ITU", "CRC-6/G-704"}
        };

        public static CRCModel CRC7 => new CRCModel
        {
            Width = 7,
            Polynomial = 0x9,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x75,
            Names = new[] {"CRC-7", "CRC-7/MMC"}
        };

        public static CRCModel CRC7_ROHC => new CRCModel
        {
            Width = 7,
            Polynomial = 0x4F,
            InitialValue = 0x7F,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x53,
            Names = new[] {"CRC-7/ROHC"}
        };

        public static CRCModel CRC7_UMTS => new CRCModel
        {
            Width = 7,
            Polynomial = 0x45,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x61,
            Names = new[] {"CRC-7/UMTS"}
        };

        public static CRCModel CRC8 => new CRCModel
        {
            Width = 8,
            Polynomial = 0x7,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xF4,
            Names = new[] {"CRC-8", "CRC-8/SMBUS"}
        };

        public static CRCModel CRC8_AUTOSAR => new CRCModel
        {
            Width = 8,
            Polynomial = 0x2F,
            InitialValue = 0xFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFF,
            CheckValue = 0xDF,
            Names = new[] {"CRC-8/AUTOSAR"}
        };

        public static CRCModel CRC8_BLUETOOTH => new CRCModel
        {
            Width = 8,
            Polynomial = 0xA7,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x26,
            Names = new[] {"CRC-8/BLUETOOTH"}
        };

        public static CRCModel CRC8_CDMA2000 => new CRCModel
        {
            Width = 8,
            Polynomial = 0x9B,
            InitialValue = 0xFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xDA,
            Names = new[] {"CRC-8/CDMA2000"}
        };

        public static CRCModel CRC8_DARC => new CRCModel
        {
            Width = 8,
            Polynomial = 0x39,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x15,
            Names = new[] {"CRC-8/DARC"}
        };

        public static CRCModel CRC8_DVBS2 => new CRCModel
        {
            Width = 8,
            Polynomial = 0xD5,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xBC,
            Names = new[] {"CRC-8/DVB-S2"}
        };

        public static CRCModel CRC8_EBU => new CRCModel
        {
            Width = 8,
            Polynomial = 0x1D,
            InitialValue = 0xFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x97,
            Names = new[] {"CRC-8/EBU", "CRC-8/AES", "CRC-8/TECH-3250"}
        };

        public static CRCModel CRC8_GSMA => new CRCModel
        {
            Width = 8,
            Polynomial = 0x1D,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x37,
            Names = new[] {"CRC-8/GSM-A"}
        };

        public static CRCModel CRC8_GSMB => new CRCModel
        {
            Width = 8,
            Polynomial = 0x49,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFF,
            CheckValue = 0x94,
            Names = new[] {"CRC-8/GSM-B"}
        };

        public static CRCModel CRC8_ICODE => new CRCModel
        {
            Width = 8,
            Polynomial = 0x1D,
            InitialValue = 0xFD,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x7E,
            Names = new[] {"CRC-8/I-CODE"}
        };

        public static CRCModel CRC8_ITU => new CRCModel
        {
            Width = 8,
            Polynomial = 0x7,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x55,
            CheckValue = 0xA1,
            Names = new[] {"CRC-8/ITU", "CRC-8/I-432-1"}
        };

        public static CRCModel CRC8_LTE => new CRCModel
        {
            Width = 8,
            Polynomial = 0x9B,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xEA,
            Names = new[] {"CRC-8/LTE"}
        };

        public static CRCModel CRC8_MAXIM => new CRCModel
        {
            Width = 8,
            Polynomial = 0x31,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xA1,
            Names = new[] {"CRC-8/MAXIM", "DOW-CRC", "CRC-8/MAXIM-DOW"}
        };

        public static CRCModel CRC8_OPENSAFETY => new CRCModel
        {
            Width = 8,
            Polynomial = 0x2F,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x3E,
            Names = new[] {"CRC-8/OPENSAFETY"}
        };

        public static CRCModel CRC8_ROHC => new CRCModel
        {
            Width = 8,
            Polynomial = 0x7,
            InitialValue = 0xFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xD0,
            Names = new[] {"CRC-8/ROHC"}
        };

        public static CRCModel CRC8_SAEJ1850 => new CRCModel
        {
            Width = 8,
            Polynomial = 0x1D,
            InitialValue = 0xFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFF,
            CheckValue = 0x4B,
            Names = new[] {"CRC-8/SAE-J1850"}
        };

        public static CRCModel CRC8_WCDMA => new CRCModel
        {
            Width = 8,
            Polynomial = 0x9B,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x25,
            Names = new[] {"CRC-8/WCDMA"}
        };

        public static CRCModel CRC8_MIFAREMAD => new CRCModel
        {
            Width = 8,
            Polynomial = 0x1D,
            InitialValue = 0xC7,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x99,
            Names = new[] {"CRC-8/MIFARE-MAD"}
        };

        public static CRCModel CRC8_NRSC5 => new CRCModel
        {
            Width = 8,
            Polynomial = 0x31,
            InitialValue = 0xFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xF7,
            Names = new[] {"CRC-8/NRSC-5"}
        };

        public static CRCModel CRC10 => new CRCModel
        {
            Width = 10,
            Polynomial = 0x233,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x199,
            Names = new[] {"CRC-10", "CRC-10/ATM", "CRC-10/I-610"}
        };

        public static CRCModel CRC10_CDMA2000 => new CRCModel
        {
            Width = 10,
            Polynomial = 0x3D9,
            InitialValue = 0x3FF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x233,
            Names = new[] {"CRC-10/CDMA2000"}
        };

        public static CRCModel CRC10_GSM => new CRCModel
        {
            Width = 10,
            Polynomial = 0x175,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x3FF,
            CheckValue = 0x12A,
            Names = new[] {"CRC-10/GSM"}
        };

        public static CRCModel CRC11 => new CRCModel
        {
            Width = 11,
            Polynomial = 0x385,
            InitialValue = 0x1A,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x5A3,
            Names = new[] {"CRC-11", "CRC-11/FLEXRAY"}
        };

        public static CRCModel CRC11_UMTS => new CRCModel
        {
            Width = 11,
            Polynomial = 0x307,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x61,
            Names = new[] {"CRC-11/UMTS"}
        };

        public static CRCModel CRC12_CDMA2000 => new CRCModel
        {
            Width = 12,
            Polynomial = 0xF13,
            InitialValue = 0xFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xD4D,
            Names = new[] {"CRC-12/CDMA2000"}
        };

        public static CRCModel CRC12_DECT => new CRCModel
        {
            Width = 12,
            Polynomial = 0x80F,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xF5B,
            Names = new[] {"CRC-12/DECT", "X-CRC-12"}
        };

        public static CRCModel CRC12_GSM => new CRCModel
        {
            Width = 12,
            Polynomial = 0xD31,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFF,
            CheckValue = 0xB34,
            Names = new[] {"CRC-12/GSM"}
        };

        public static CRCModel CRC12_UMTS => new CRCModel
        {
            Width = 12,
            Polynomial = 0x80F,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xDAF,
            Names = new[] {"CRC-12/UMTS", "CRC-12/3GPP"}
        };

        public static CRCModel CRC13_BBC => new CRCModel
        {
            Width = 13,
            Polynomial = 0x1CF5,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x4FA,
            Names = new[] {"CRC-13/BBC"}
        };

        public static CRCModel CRC14_DARC => new CRCModel
        {
            Width = 14,
            Polynomial = 0x805,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x82D,
            Names = new[] {"CRC-14/DARC"}
        };

        public static CRCModel CRC14_GSM => new CRCModel
        {
            Width = 14,
            Polynomial = 0x202D,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x3FFF,
            CheckValue = 0x30AE,
            Names = new[] {"CRC-14/GSM"}
        };

        public static CRCModel CRC15 => new CRCModel
        {
            Width = 15,
            Polynomial = 0x4599,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x59E,
            Names = new[] {"CRC-15", "CRC-15/CAN"}
        };

        public static CRCModel CRC15_MPT1327 => new CRCModel
        {
            Width = 15,
            Polynomial = 0x6815,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x1,
            CheckValue = 0x2566,
            Names = new[] {"CRC-15/MPT1327"}
        };

        public static CRCModel ARC => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8005,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xBB3D,
            Names = new[] {"CRC-16", "ARC", "CRC-IBM", "CRC-16/ARC", "CRC-16/LHA"}
        };

        public static CRCModel CRC16_AUGCCITT => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0x1D0F,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xE5CC,
            Names = new[] {"CRC-16/AUG-CCITT", "CRC-16/SPI-FUJITSU"}
        };

        public static CRCModel CRC16_BUYPASS => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8005,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xFEE8,
            Names = new[] {"CRC-16/BUYPASS", "CRC-16/VERIFONE", "CRC-16/UMTS"}
        };

        public static CRCModel CRC16_CCITTFALSE => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0xFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x29B1,
            Names = new[] {"CRC-16/CCITT-FALSE", "CRC-16/AUTOSAR", "CRC-16/IBM-3740"}
        };

        public static CRCModel CRC16_CDMA2000 => new CRCModel
        {
            Width = 16,
            Polynomial = 0xC867,
            InitialValue = 0xFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x4C06,
            Names = new[] {"CRC-16/CDMA2000"}
        };

        public static CRCModel CRC16_CMS => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8005,
            InitialValue = 0xFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xAEE7,
            Names = new[] {"CRC-16/CMS"}
        };

        public static CRCModel CRC16_DDS110 => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8005,
            InitialValue = 0x800D,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x9ECF,
            Names = new[] {"CRC-16/DDS-110"}
        };

        public static CRCModel CRC16_DECTR => new CRCModel
        {
            Width = 16,
            Polynomial = 0x589,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x1,
            CheckValue = 0x7E,
            Names = new[] {"CRC-16/DECT-R", "R-CRC-16"}
        };

        public static CRCModel CRC16_DECTX => new CRCModel
        {
            Width = 16,
            Polynomial = 0x589,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x7F,
            Names = new[] {"CRC-16/DECT-X", "X-CRC-16"}
        };

        public static CRCModel CRC16_DNP => new CRCModel
        {
            Width = 16,
            Polynomial = 0x3D65,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFF,
            CheckValue = 0xEA82,
            Names = new[] {"CRC-16/DNP"}
        };

        public static CRCModel CRC16_EN13757 => new CRCModel
        {
            Width = 16,
            Polynomial = 0x3D65,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFF,
            CheckValue = 0xC2B7,
            Names = new[] {"CRC-16/EN13757"}
        };

        public static CRCModel CRC16_GENIBUS => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0xFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFF,
            CheckValue = 0xD64E,
            Names = new[] {"CRC-16/GENIBUS", "CRC-16/EPC", "CRC-16/I-CODE", "CRC-16/DARC", "CRC-16/EPC-C1G2"}
        };

        public static CRCModel CRC16_GSM => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFF,
            CheckValue = 0xCE3C,
            Names = new[] {"CRC-16/GSM"}
        };

        public static CRCModel CRC16_LJ1200 => new CRCModel
        {
            Width = 16,
            Polynomial = 0x6F63,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xBDF4,
            Names = new[] {"CRC-16/LJ1200"}
        };

        public static CRCModel CRC16_MAXIM => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8005,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFF,
            CheckValue = 0x44C2,
            Names = new[] {"CRC-16/MAXIM", "CRC-16/MAXIM-DOW"}
        };

        public static CRCModel CRC16_MCRF4XX => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0xFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x6F91,
            Names = new[] {"CRC-16/MCRF4XX"}
        };

        public static CRCModel CRC16_OPENSAFETYA => new CRCModel
        {
            Width = 16,
            Polynomial = 0x5935,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x5D38,
            Names = new[] {"CRC-16/OPENSAFETY-A"}
        };

        public static CRCModel CRC16_OPENSAFETYB => new CRCModel
        {
            Width = 16,
            Polynomial = 0x755B,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x20FE,
            Names = new[] {"CRC-16/OPENSAFETY-B"}
        };

        public static CRCModel CRC16_PROFIBUS => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1DCF,
            InitialValue = 0xFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFF,
            CheckValue = 0xA819,
            Names = new[] {"CRC-16/PROFIBUS", "CRC-16/IEC-61158-2"}
        };

        public static CRCModel CRC16_RIELLO => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0xB2AA,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x63D0,
            Names = new[] {"CRC-16/RIELLO"}
        };

        public static CRCModel CRC16_T10DIF => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8BB7,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xD0DB,
            Names = new[] {"CRC-16/T10-DIF"}
        };

        public static CRCModel CRC16_TELEDISK => new CRCModel
        {
            Width = 16,
            Polynomial = 0xA097,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xFB3,
            Names = new[] {"CRC-16/TELEDISK"}
        };

        public static CRCModel CRC16_TMS37157 => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0x89EC,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x26B1,
            Names = new[] {"CRC-16/TMS37157"}
        };

        public static CRCModel CRC16_USB => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8005,
            InitialValue = 0xFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFF,
            CheckValue = 0xB4C8,
            Names = new[] {"CRC-16/USB"}
        };

        public static CRCModel CRCA => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0xC6C6,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xBF05,
            Names = new[] {"CRC-A", "CRC-16/ISO-IEC-14443-3-A"}
        };

        public static CRCModel KERMIT => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x2189,
            Names = new[]
            {
                "KERMIT", "CRC-16/CCITT", "CRC-16/CCITT-TRUE", "CRC-CCITT", "CRC-16/KERMIT", "CRC-16/V-41-LSB"
            }
        };

        public static CRCModel MODBUS => new CRCModel
        {
            Width = 16,
            Polynomial = 0x8005,
            InitialValue = 0xFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x4B37,
            Names = new[] {"MODBUS", "CRC-16/MODBUS"}
        };

        public static CRCModel X25 => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0xFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFF,
            CheckValue = 0x906E,
            Names = new[]
            {
                "X-25", "CRC-16/IBM-SDLC", "CRC-16/ISO-HDLC", "CRC-16/ISO-IEC-14443-3-B", "CRC-B", "CRC-16/X-25"
            }
        };

        public static CRCModel XMODEM => new CRCModel
        {
            Width = 16,
            Polynomial = 0x1021,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x31C3,
            Names = new[] {"XMODEM", "ZMODEM", "CRC-16/ACORN", "CRC-16/XMODEM", "CRC-16/V-41-MSB"}
        };

        public static CRCModel CRC16_NRSC5 => new CRCModel
        {
            Width = 16,
            Polynomial = 0x080B,
            InitialValue = 0xFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xA066,
            Names = new[] {"CRC-16/NRSC-5"}
        };

        public static CRCModel CRC17_CANFD => new CRCModel
        {
            Width = 17,
            Polynomial = 0x1685B,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x4F03,
            Names = new[] {"CRC-17/CAN-FD"}
        };

        public static CRCModel CRC21_CANFD => new CRCModel
        {
            Width = 21,
            Polynomial = 0x102899,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xED841,
            Names = new[] {"CRC-21/CAN-FD"}
        };

        public static CRCModel CRC24 => new CRCModel
        {
            Width = 24,
            Polynomial = 0x864CFB,
            InitialValue = 0xB704CE,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x21CF02,
            Names = new[] {"CRC-24", "CRC-24/OPENPGP"}
        };

        public static CRCModel CRC24_BLE => new CRCModel
        {
            Width = 24,
            Polynomial = 0x65B,
            InitialValue = 0x555555,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xC25A56,
            Names = new[] {"CRC-24/BLE"}
        };

        public static CRCModel CRC24_FLEXRAYA => new CRCModel
        {
            Width = 24,
            Polynomial = 0x5D6DCB,
            InitialValue = 0xFEDCBA,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x7979BD,
            Names = new[] {"CRC-24/FLEXRAY-A"}
        };

        public static CRCModel CRC24_FLEXRAYB => new CRCModel
        {
            Width = 24,
            Polynomial = 0x5D6DCB,
            InitialValue = 0xABCDEF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x1F23B8,
            Names = new[] {"CRC-24/FLEXRAY-B"}
        };

        public static CRCModel CRC24_INTERLAKEN => new CRCModel
        {
            Width = 24,
            Polynomial = 0x328B63,
            InitialValue = 0xFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFFFF,
            CheckValue = 0xB4F3E6,
            Names = new[] {"CRC-24/INTERLAKEN"}
        };

        public static CRCModel CRC24_LTEA => new CRCModel
        {
            Width = 24,
            Polynomial = 0x864CFB,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xCDE703,
            Names = new[] {"CRC-24/LTE-A"}
        };

        public static CRCModel CRC24_LTEB => new CRCModel
        {
            Width = 24,
            Polynomial = 0x800063,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x23EF52,
            Names = new[] {"CRC-24/LTE-B"}
        };

        public static CRCModel CRC24_OS9 => new CRCModel
        {
            Width = 24,
            Polynomial = 0x800063,
            InitialValue = 0xFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFFFF,
            CheckValue = 0x200FA5,
            Names = new[] {"CRC-24/OS-9"}
        };

        public static CRCModel CRC30_CDMA => new CRCModel
        {
            Width = 30,
            Polynomial = 0x2030B9C7,
            InitialValue = 0x3FFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x3FFFFFFF,
            CheckValue = 0x4C34ABF,
            Names = new[] {"CRC-30/CDMA"}
        };

        public static CRCModel CRC31_PHILIPS => new CRCModel
        {
            Width = 31,
            Polynomial = 0x4C11DB7,
            InitialValue = 0x7FFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x7FFFFFFF,
            CheckValue = 0xCE9E46C,
            Names = new[] {"CRC-31/PHILLIPS"}
        };

        public static CRCModel CRC32 => new CRCModel
        {
            Width = 32,
            Polynomial = 0x4C11DB7,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFFFFFF,
            CheckValue = 0xCBF43926,
            Names = new[] {"CRC-32", "CRC-32/ADCCP", "CRC-32/V-42", "CRC-32/XZ", "PKZIP", "CRC-32/ISO-HDLC"}
        };

        public static CRCModel CRC32_AUTOSAR => new CRCModel
        {
            Width = 32,
            Polynomial = 0xF4ACFB13,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFFFFFF,
            CheckValue = 0x1697D06A,
            Names = new[] {"CRC-32/AUTOSAR"}
        };

        public static CRCModel CRC32_BZIP2 => new CRCModel
        {
            Width = 32,
            Polynomial = 0x4C11DB7,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFFFFFF,
            CheckValue = 0xFC891918,
            Names = new[] {"CRC-32/BZIP2", "CRC-32/AAL5", "CRC-32/DECT-B", "B-CRC-32"}
        };

        public static CRCModel CRC32C => new CRCModel
        {
            Width = 32,
            Polynomial = 0x1EDC6F41,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFFFFFF,
            CheckValue = 0xE3069283,
            Names = new[] {"CRC-32C", "CRC-32/BASE91-C", "CRC-32/CASTAGNOLI", "CRC-32/INTERLAKEN", "CRC-32/ISCSI"}
        };

        public static CRCModel CRC32D => new CRCModel
        {
            Width = 32,
            Polynomial = 0xA833982B,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFFFFFF,
            CheckValue = 0x87315576,
            Names = new[] {"CRC-32D", "CRC-32/BASE91-D"}
        };

        public static CRCModel CRC32_MPEG2 => new CRCModel
        {
            Width = 32,
            Polynomial = 0x4C11DB7,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x376E6E7,
            Names = new[] {"CRC-32/MPEG-2"}
        };

        public static CRCModel CRC32_POSIX => new CRCModel
        {
            Width = 32,
            Polynomial = 0x4C11DB7,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x376E6E7,
            Names = new[] {"CRC-32/POSIX", "CKSUM"}
        };

        public static CRCModel CRC32Q => new CRCModel
        {
            Width = 32,
            Polynomial = 0x814141AB,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x3010BF7F,
            Names = new[] {"CRC-32Q", "CRC-32/AIXM"}
        };

        public static CRCModel JAMCRC => new CRCModel
        {
            Width = 32,
            Polynomial = 0x4C11DB7,
            InitialValue = 0xFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x340BC6D9,
            Names = new[] {"JAMCRC", "CRC-32/JAMCRC"}
        };

        public static CRCModel XFER => new CRCModel
        {
            Width = 32,
            Polynomial = 0xAF,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0xBD0BE338,
            Names = new[] {"XFER", "CRC-32/XFER"}
        };

        public static CRCModel CRC32_CDROMEDC => new CRCModel
        {
            Width = 32,
            Polynomial = 0x8001801B,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x6EC2EDC4,
            Names = new[] {"CRC-32/CD-ROM-EDC"}
        };

        public static CRCModel CRC40_GSM => new CRCModel
        {
            Width = 40,
            Polynomial = 0x4820009,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFFFFFFFF,
            CheckValue = 0xD4164FC646,
            Names = new[] {"CRC-40/GSM"}
        };

        public static CRCModel CRC64 => new CRCModel
        {
            Width = 64,
            Polynomial = 0x42F0E1EBA9EA3693,
            InitialValue = 0x0,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0x0,
            CheckValue = 0x6C40DF5F0B497347,
            Names = new[] {"CRC-64", "CRC-64/ECMA-182"}
        };

        public static CRCModel CRC64_GOISO => new CRCModel
        {
            Width = 64,
            Polynomial = 0x1B,
            InitialValue = 0xFFFFFFFFFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFFFFFFFFFFFFFF,
            CheckValue = 0xB90956C775A41001,
            Names = new[] {"CRC-64/GO-ISO"}
        };

        public static CRCModel CRC64_WE => new CRCModel
        {
            Width = 64,
            Polynomial = 0x42F0E1EBA9EA3693,
            InitialValue = 0xFFFFFFFFFFFFFFFF,
            ReflectIn = false,
            ReflectOut = false,
            XorOut = 0xFFFFFFFFFFFFFFFF,
            CheckValue = 0x62EC59E3F1A4F00A,
            Names = new[] {"CRC-64/WE"}
        };

        public static CRCModel CRC64_XZ => new CRCModel
        {
            Width = 64,
            Polynomial = 0x42F0E1EBA9EA3693,
            InitialValue = 0xFFFFFFFFFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0xFFFFFFFFFFFFFFFF,
            CheckValue = 0x995DC9BBDF1939FA,
            Names = new[] {"CRC-64/XZ", "CRC-64/GO-ECMA"}
        };


        public static CRCModel CRC64_1B => new CRCModel
        {
            Width = 64,
            Polynomial = 0x1B,
            InitialValue = 0x0,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0x46A5A9388A5BEFFE,
            Names = new[] {"CRC-64/1B"}
        };

        public static CRCModel CRC64_Jones => new CRCModel
        {
            Width = 64,
            Polynomial = 0xAD93D23594C935A9,
            InitialValue = 0xFFFFFFFFFFFFFFFF,
            ReflectIn = true,
            ReflectOut = true,
            XorOut = 0x0,
            CheckValue = 0xCAA717168609F281,
            Names = new[] {"CRC-64/Jones"}
        };
    }
}