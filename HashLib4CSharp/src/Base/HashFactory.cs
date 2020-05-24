using System.Security.Cryptography;
using HashLib4CSharp.Adapter;
using HashLib4CSharp.Checksum;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Enum;
using HashLib4CSharp.Hash128;
using HashLib4CSharp.Hash32;
using HashLib4CSharp.Hash64;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.KDF;
using HashLib4CSharp.MAC;
using HashLib4CSharp.Params;

namespace HashLib4CSharp.Base
{
    public static class HashFactory
    {
        public static class NullDigestFactory
        {
            public static IHash CreateNullDigest()
            {
                return new NullDigest.NullDigest();
            }
        }

        public static class Checksum
        {
            public static IHash CreateAdler32()
            {
                return new Adler32();
            }

            public static class CRC
            {
                public static IHash CreateCrc32Castagnoli()
                {
                    return new Crc32Castagnoli();
                }

                public static IHash CreateCrc32PKZip()
                {
                    return new Crc32PKZip();
                }
            }
        }

        public static class Hash32
        {
            public static IHash CreateAP()
            {
                return new AP();
            }

            public static IHash CreateBernstein()
            {
                return new Bernstein();
            }

            public static IHash CreateBernstein1()
            {
                return new Bernstein1();
            }

            public static IHash CreateBKDR()
            {
                return new BKDR();
            }

            public static IHash CreateDEK()
            {
                return new DEK();
            }

            public static IHash CreateDJB()
            {
                return new DJB();
            }

            public static IHash CreateELF()
            {
                return new ELF();
            }

            public static IHash CreateFNV()
            {
                return new FNV();
            }

            public static IHash CreateFNV1a()
            {
                return new FNV1a();
            }

            public static IHash CreateJenkins3(int initialValue = 0)
            {
                return new Jenkins3(initialValue);
            }

            public static IHash CreateJS()
            {
                return new JS();
            }

            public static IHashWithKey CreateMurmur2()
            {
                return new Murmur2();
            }

            public static IHashWithKey CreateMurmurHash3_x86_32()
            {
                return new MurmurHash3_x86_32();
            }

            public static IHash CreateOneAtTime()
            {
                return new OneAtTime();
            }

            public static IHash CreatePJW()
            {
                return new PJW();
            }

            public static IHash CreateRotating()
            {
                return new Rotating();
            }

            public static IHash CreateRS()
            {
                return new RS();
            }

            public static IHash CreateSDBM()
            {
                return new SDBM();
            }

            public static IHash CreateShiftAndXor()
            {
                return new ShiftAndXor();
            }

            public static IHash CreateSuperFast()
            {
                return new SuperFast();
            }

            public static IHashWithKey CreateXXHash32()
            {
                return new XXHash32();
            }
        }

        public static class Hash64
        {
            public static IHash CreateFNV64()
            {
                return new FNV64();
            }

            public static IHash CreateFV1a64()
            {
                return new FNV1a64();
            }

            public static IHashWithKey CreateMurmur2_64()
            {
                return new Murmur2_64();
            }

            public static IHashWithKey CreateSipHash64_2_4()
            {
                return new SipHash64_2_4();
            }

            public static IHashWithKey CreateXXHash64()
            {
                return new XXHash64();
            }
        }

        public static class Hash128
        {
            public static IHashWithKey CreateSipHash128_2_4()
            {
                return new SipHash128_2_4();
            }

            public static IHashWithKey CreateMurmurHash3_x86_128()
            {
                return new MurmurHash3_x86_128();
            }

            public static IHashWithKey CreateMurmurHash3_x64_128()
            {
                return new MurmurHash3_x64_128();
            }
        }

        public static class Crypto
        {
            public static IHash CreateBlake2B(Blake2BConfig config = null, Blake2BTreeConfig treeConfig = null)
            {
                return new Blake2B(config ?? Blake2BConfig.DefaultConfig, treeConfig);
            }

            public static IHash CreateBlake2B_160()
            {
                return CreateBlake2B(new Blake2BConfig(HashSize.HashSize160));
            }

            public static IHash CreateBlake2B_256()
            {
                return CreateBlake2B(new Blake2BConfig(HashSize.HashSize256));
            }

            public static IHash CreateBlake2B_384()
            {
                return CreateBlake2B(new Blake2BConfig(HashSize.HashSize384));
            }

            public static IHash CreateBlake2B_512()
            {
                return CreateBlake2B(new Blake2BConfig());
            }

            public static IHash CreateBlake2S(Blake2SConfig config = null, Blake2STreeConfig treeConfig = null)
            {
                return new Blake2S(config ?? Blake2SConfig.DefaultConfig, treeConfig);
            }

            public static IHash CreateBlake2S_128()
            {
                return CreateBlake2S(new Blake2SConfig(HashSize.HashSize128));
            }

            public static IHash CreateBlake2S_160()
            {
                return CreateBlake2S(new Blake2SConfig(HashSize.HashSize160));
            }

            public static IHash CreateBlake2S_224()
            {
                return CreateBlake2S(new Blake2SConfig(HashSize.HashSize224));
            }

            public static IHash CreateBlake2S_256()
            {
                return CreateBlake2S(new Blake2SConfig());
            }

            public static IHash CreateBlake2BP(int hashSize, byte[] key)
            {
                return new Blake2BP(hashSize, key);
            }

            public static IHash CreateBlake2SP(int hashSize, byte[] key)
            {
                return new Blake2SP(hashSize, key);
            }

            public static IHash CreateBlake3_256(byte[] key)
            {
                return new Blake3(HashSize.HashSize256, key);
            }

            public static IHash CreateBlake3_256()
            {
                return new Blake3(HashSize.HashSize256, new byte[0]);
            }

            public static IHash CreateGost()
            {
                return new Gost();
            }

            public static IHash CreateGOST3411_2012_256()
            {
                return new GOST3411_2012_256();
            }

            public static IHash CreateGOST3411_2012_512()
            {
                return new GOST3411_2012_512();
            }

            public static IHash CreateGrindahl256()
            {
                return new Grindahl256();
            }

            public static IHash CreateGrindahl512()
            {
                return new Grindahl512();
            }

            public static IHash CreateHAS160()
            {
                return new HAS160();
            }

            public static IHash CreateHaval_3_128()
            {
                return new Haval_3_128();
            }

            public static IHash CreateHaval_4_128()
            {
                return new Haval_4_128();
            }

            public static IHash CreateHaval_5_128()
            {
                return new Haval_5_128();
            }

            public static IHash CreateHaval_3_160()
            {
                return new Haval_3_160();
            }

            public static IHash CreateHaval_4_160()
            {
                return new Haval_4_160();
            }

            public static IHash CreateHaval_5_160()
            {
                return new Haval_5_160();
            }

            public static IHash CreateHaval_3_192()
            {
                return new Haval_3_192();
            }

            public static IHash CreateHaval_4_192()
            {
                return new Haval_4_192();
            }

            public static IHash CreateHaval_5_192()
            {
                return new Haval_5_192();
            }

            public static IHash CreateHaval_3_224()
            {
                return new Haval_3_224();
            }

            public static IHash CreateHaval_4_224()
            {
                return new Haval_4_224();
            }

            public static IHash CreateHaval_5_224()
            {
                return new Haval_5_224();
            }

            public static IHash CreateHaval_3_256()
            {
                return new Haval_3_256();
            }

            public static IHash CreateHaval_4_256()
            {
                return new Haval_4_256();
            }

            public static IHash CreateHaval_5_256()
            {
                return new Haval_5_256();
            }

            public static IHash CreateKeccak_224()
            {
                return new Keccak_224();
            }

            public static IHash CreateKeccak_256()
            {
                return new Keccak_256();
            }

            public static IHash CreateKeccak_288()
            {
                return new Keccak_288();
            }

            public static IHash CreateKeccak_384()
            {
                return new Keccak_384();
            }

            public static IHash CreateKeccak_512()
            {
                return new Keccak_512();
            }

            public static IHash CreateMD2()
            {
                return new MD2();
            }

            public static IHash CreateMD4()
            {
                return new MD4();
            }

            public static IHash CreateMD5()
            {
                return new HashLib4CSharp.Crypto.MD5();
            }

            public static IHash CreatePanama()
            {
                return new Panama();
            }

            public static IHash CreateRadioGatun32()
            {
                return new RadioGatun32();
            }

            public static IHash CreateRadioGatun64()
            {
                return new RadioGatun64();
            }

            public static IHash CreateRIPEMD()
            {
                return new RIPEMD();
            }

            public static IHash CreateRIPEMD128()
            {
                return new RIPEMD128();
            }

            public static IHash CreateRIPEMD160()
            {
                return new RIPEMD160();
            }

            public static IHash CreateRIPEMD256()
            {
                return new RIPEMD256();
            }

            public static IHash CreateRIPEMD320()
            {
                return new RIPEMD320();
            }

            public static IHash CreateSHA0()
            {
                return new SHA0();
            }

            public static IHash CreateSHA1()
            {
                return new HashLib4CSharp.Crypto.SHA1();
            }

            public static IHash CreateSHA2_224()
            {
                return new SHA2_224();
            }

            public static IHash CreateSHA2_256()
            {
                return new SHA2_256();
            }

            public static IHash CreateSHA2_384()
            {
                return new SHA2_384();
            }

            public static IHash CreateSHA2_512()
            {
                return new SHA2_512();
            }

            public static IHash CreateSHA2_512_224()
            {
                return new SHA2_512_224();
            }

            public static IHash CreateSHA2_512_256()
            {
                return new SHA2_512_256();
            }

            public static IHash CreateSHA3_224()
            {
                return new SHA3_224();
            }

            public static IHash CreateSHA3_256()
            {
                return new SHA3_256();
            }

            public static IHash CreateSHA3_384()
            {
                return new SHA3_384();
            }

            public static IHash CreateSHA3_512()
            {
                return new SHA3_512();
            }

            public static IHash CreateSnefru_8_128()
            {
                return Snefru_8.CreateHashSize128();
            }

            public static IHash CreateSnefru_8_256()
            {
                return Snefru_8.CreateHashSize256();
            }

            public static IHash CreateTiger_3_128()
            {
                return Tiger_128.CreateRound3();
            }

            public static IHash CreateTiger_3_160()
            {
                return Tiger_160.CreateRound3();
            }

            public static IHash CreateTiger_3_192()
            {
                return Tiger_192.CreateRound3();
            }

            public static IHash CreateTiger_4_128()
            {
                return Tiger_128.CreateRound4();
            }

            public static IHash CreateTiger_4_160()
            {
                return Tiger_160.CreateRound4();
            }

            public static IHash CreateTiger_4_192()
            {
                return Tiger_192.CreateRound4();
            }

            public static IHash CreateTiger_5_128()
            {
                return Tiger_128.CreateRound5();
            }

            public static IHash CreateTiger_5_160()
            {
                return Tiger_160.CreateRound5();
            }

            public static IHash CreateTiger_5_192()
            {
                return Tiger_192.CreateRound5();
            }

            public static IHash CreateTiger2_3_128()
            {
                return Tiger2_128.CreateRound3();
            }

            public static IHash CreateTiger2_3_160()
            {
                return Tiger2_160.CreateRound3();
            }

            public static IHash CreateTiger2_3_192()
            {
                return Tiger2_192.CreateRound3();
            }

            public static IHash CreateTiger2_4_128()
            {
                return Tiger2_128.CreateRound4();
            }

            public static IHash CreateTiger2_4_160()
            {
                return Tiger2_160.CreateRound4();
            }

            public static IHash CreateTiger2_4_192()
            {
                return Tiger2_192.CreateRound4();
            }

            public static IHash CreateTiger2_5_128()
            {
                return Tiger2_128.CreateRound5();
            }

            public static IHash CreateTiger2_5_160()
            {
                return Tiger2_160.CreateRound5();
            }

            public static IHash CreateTiger2_5_192()
            {
                return Tiger2_192.CreateRound5();
            }

            public static IHash CreateWhirlPool()
            {
                return new WhirlPool();
            }
        }

        public static class HMAC
        {
            public static IHMACNotBuiltIn CreateHMAC(IHash hash, byte[] hmacKey)
            {
                return HMACNotBuiltIn.CreateHMAC(hash, hmacKey);
            }
        }

        public static class KMAC
        {
            public static IKMACNotBuiltIn CreateKMAC128(byte[] kmacKey, byte[] customization,
                ulong outputLengthInBits)
            {
                return KMACNotBuiltIn.CreateKMAC128(kmacKey, customization, outputLengthInBits);
            }

            public static IKMACNotBuiltIn CreateKMAC256(byte[] kmacKey, byte[] customization,
                ulong outputLengthInBits)
            {
                return KMACNotBuiltIn.CreateKMAC256(kmacKey, customization, outputLengthInBits);
            }
        }

        public static class Blake2BMAC
        {
            public static IBlake2BMACNotBuiltIn CreateBlake2BMAC(byte[] key, byte[] salt, byte[] personalization,
                int outputLengthInBits)
            {
                return Blake2BMACNotBuiltIn.CreateBlake2BMAC(key, salt,
                    personalization, outputLengthInBits);
            }
        }

        public static class Blake2SMAC
        {
            public static IBlake2SMACNotBuiltIn CreateBlake2SMAC(byte[] key, byte[] salt, byte[] personalization,
                int outputLengthInBits)
            {
                return Blake2SMACNotBuiltIn.CreateBlake2SMAC(key, salt,
                    personalization, outputLengthInBits);
            }
        }

        public static class KDF
        {
            public static class PBKDFArgon2
            {
                public static IPBKDFArgon2NotBuiltIn CreatePBKDFArgon2(byte[] password, Argon2Parameters parameters)
                {
                    return new PBKDFArgon2NotBuiltIn(password, parameters);
                }
            }

            public static class PBKDFBlake3
            {
                public static IPBKDFBlake3NotBuiltIn CreatePBKDFBlake3(byte[] srcKey, byte[] ctx)
                {
                    return new PBKDFBlake3NotBuiltIn(srcKey, ctx);
                }
            }

            public static class PBKDF2HMAC
            {
                /// <summary>
                /// Initializes a new interface instance of the PBKDF2HMAC class using a password, a salt, a number
                /// of iterations and an instance of an "IHash" to be transformed to an "IHMACNotBuiltIn" so it
                /// can be used to derive the key.
                /// </summary>
                /// <param name="hash">The name of the "IHash" to be transformed to an "IHMACNotBuiltIn" Instance so
                /// it can be used to derive the key.</param>
                /// <param name="password">The password to derive the key for.</param>
                /// <param name="salt">The salt to use to derive the key.</param>
                /// <param name="iterations">The number of iterations used to derive the key.</param>
                public static IPBKDF2HMACNotBuiltIn CreatePBKDF2HMAC(IHash hash, byte[] password,
                    byte[] salt, uint iterations)
                {
                    return new PBKDF2HMACNotBuiltIn(hash, password, salt, iterations);
                }
            }

            public static class PBKDFScrypt
            {
                public static IPBKDFScryptNotBuiltIn CreatePBKDFScrypt(byte[] password,
                    byte[] salt, int cost, int blockSize, int parallelism)
                {
                    return new PBKDFScryptNotBuiltIn(password, salt,
                        cost, blockSize, parallelism);
                }
            }
        }

        public static class XOF
        {
            public static IXOF CreateBlake2XB(Blake2XBConfig config, ulong xofSizeInBits)
            {
                return new Blake2XB(config)
                {
                    XofSizeInBits = xofSizeInBits
                };
            }

            public static IXOF CreateBlake2XB(byte[] key, ulong xofSizeInBits)
            {
                return CreateBlake2XB(Blake2XBConfig.CreateBlake2XBConfig(new Blake2BConfig {Key = key}, null),
                    xofSizeInBits);
            }

            public static IXOF CreateBlake2XS(Blake2XSConfig config, ulong xofSizeInBits)
            {
                return new Blake2XS(config)
                {
                    XofSizeInBits = xofSizeInBits
                };
            }

            public static IXOF CreateBlake2XS(byte[] key, ulong xofSizeInBits)
            {
                return CreateBlake2XS(Blake2XSConfig.CreateBlake2XSConfig(new Blake2SConfig {Key = key}, null),
                    xofSizeInBits);
            }


            public static IXOF CreateBlake3XOF(byte[] key, ulong xofSizeInBits)
            {
                return new Blake3XOF(32, key) {XofSizeInBits = xofSizeInBits};
            }

            public static IXOF CreateCShake_128(byte[] n, byte[] s, ulong xofSizeInBits)
            {
                return new CShake_128(n, s) {XofSizeInBits = xofSizeInBits};
            }

            public static IXOF CreateCShake_256(byte[] n, byte[] s, ulong xofSizeInBits)
            {
                return new CShake_256(n, s) {XofSizeInBits = xofSizeInBits};
            }

            public static IXOF CreateKMAC128XOF(byte[] kmacKey, byte[] customization,
                ulong xofSizeInBits)
            {
                return new KMAC128XOF(kmacKey, customization)
                {
                    XofSizeInBits = xofSizeInBits
                };
            }

            public static IXOF CreateKMAC256XOF(byte[] kmacKey, byte[] customization,
                ulong xofSizeInBits)
            {
                return new KMAC256XOF(kmacKey, customization)
                {
                    XofSizeInBits = xofSizeInBits
                };
            }

            public static IXOF CreateShake_128(ulong xofSizeInBits)
            {
                return new Shake_128 {XofSizeInBits = xofSizeInBits};
            }

            public static IXOF CreateShake_256(ulong xofSizeInBits)
            {
                return new Shake_256 {XofSizeInBits = xofSizeInBits};
            }
        }

        public static class Adapter
        {
            public static HashAlgorithm CreateHashAlgorithmFromHash(IHash hash)
            {
                return new HashToHashAlgorithmAdapter(hash);
            }

            public static System.Security.Cryptography.HMAC CreateHMACFromHMACNotBuiltIn(IHMACNotBuiltIn hmacNotBuiltIn)
            {
                return new HMACNotBuiltInToHMACAdapter(hmacNotBuiltIn);
            }

            public static DeriveBytes CreateDeriveBytesFromKDFNotBuiltIn(IKDFNotBuiltIn kdfNotBuiltIn)
            {
                return new KDFNotBuiltInToDeriveBytesAdapter(kdfNotBuiltIn);
            }
        }
    }
}