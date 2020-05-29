using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.KDF;
using HashLib4CSharp.Utils;
using NUnit.Framework;

namespace HashLib4CSharp.Tests
{
    internal abstract class KDFTestBase : HashTestBase
    {
        protected int ByteCount { get; set; }
        protected IKDFNotBuiltIn KdfInstance { get; set; }
        protected byte[] Password { get; set; }
        protected byte[] Salt { get; set; }
        protected static int Zero => 0;

        [Test]
        public void TestInvalidByteCountThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() => KdfInstance.GetBytes(Zero));

        [Test]
        public void TestCancellationTokenWorks()
        {
            LargeMemoryStream.Position = 0;
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();
            Assert.CatchAsync<OperationCanceledException>(() =>
                KdfInstance.GetBytesAsync(ByteCount, cancellationTokenSource.Token));
        }

        [Test]
        public void TestKdfCloningWorks()
        {
            var kdfInstanceClone = KdfInstance.Clone();

            var result = KdfInstance.GetBytes(ByteCount);
            var resultClone = kdfInstanceClone.GetBytes(ByteCount);

            AssertAreEqual(result, resultClone, $"Error in '{KdfInstance.Name}' cloning");
        }

        [Test]
        public async Task TestSyncAndAsyncMatches()
        {
            ExpectedString = Converters.ConvertBytesToHexString(SyncComputation());
            ActualString = Converters.ConvertBytesToHexString(await ASyncComputation());
            AssertAreEqual(ExpectedString, ActualString);
        }

        private byte[] SyncComputation() => KdfInstance.GetBytes(ByteCount);
        private async Task<byte[]> ASyncComputation() => await KdfInstance.GetBytesAsync(ByteCount);
    }

    internal abstract class PBKDF2HMACTestBase : KDFTestBase
    {
        private uint Iteration => (uint) ByteCount;

        [Test]
        public void TestNullHashInstanceThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDF2HMAC.CreatePBKDF2HMAC(NullHashInstance, Password, Salt, Iteration));

        [Test]
        public void TestNullPasswordThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDF2HMAC.CreatePBKDF2HMAC(HashInstance, NullBytes, Salt, Iteration));

        [Test]
        public void TestNullSaltThrowsCorrectException() =>
            Assert.Throws<ArgumentNullException>(() =>
                _ = HashFactory.KDF.PBKDF2HMAC.CreatePBKDF2HMAC(HashInstance, Password, NullBytes, Iteration));

        [Test]
        public void TestInvalidIterationThrowsCorrectException() =>
            Assert.Throws<ArgumentException>(() =>
                _ = HashFactory.KDF.PBKDF2HMAC.CreatePBKDF2HMAC(HashInstance, Password, Salt, (uint) Zero));

        [Test]
        public void TestCorrectResultIsComputed()
        {
            ActualString = Converters.ConvertBytesToHexString
                (KdfInstance.GetBytes(ByteCount));

            AssertAreEqual(ExpectedString, ActualString);
        }

        [Test]
        public async Task TestCorrectResultIsComputedAsync()
        {
            var result = await KdfInstance.GetBytesAsync(ByteCount);

            ActualString = Converters.ConvertBytesToHexString(result);

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class PBKDFScryptTestBase : KDFTestBase
    {
        protected static void DoCheckOk(string msg, byte[] password, byte[] salt, int cost,
            int blockSize, int parallelism, int outputSize) =>
            Assert.DoesNotThrow(() => HashFactory.KDF.PBKDFScrypt.CreatePBKDFScrypt(
                password,
                salt, cost, blockSize, parallelism).GetBytes(outputSize), msg);

        protected static void DoCheckIllegal(string msg, byte[] password, byte[] salt, int cost,
            int blockSize, int parallelism, int outputSize) =>
            Assert.Throws<ArgumentException>(() => HashFactory.KDF.PBKDFScrypt.CreatePBKDFScrypt(
                password,
                salt, cost, blockSize, parallelism).GetBytes(outputSize), msg);

        protected void DoTestVector(string password, string salt, int cost, int blockSize,
            int parallelism, int outputSize)
        {
            Password = Converters.ConvertStringToBytes(password, Encoding.ASCII);
            Salt = Converters.ConvertStringToBytes(salt, Encoding.ASCII);

            KdfInstance = HashFactory.KDF.PBKDFScrypt.CreatePBKDFScrypt(Password,
                Salt, cost, blockSize, parallelism);

            ActualString = Converters.ConvertBytesToHexString(KdfInstance.GetBytes(outputSize));

            AssertAreEqual(ExpectedString, ActualString);
        }
    }

    internal abstract class PBKDFBlake3TestBase : KDFTestBase
    {
        protected byte[] ctx { get; set; }
        protected byte[] fullInput { get; set; }
    }

    internal abstract class PBKDFArgon2TestBase : KDFTestBase
    {
        protected Argon2ParametersBuilder Builder { get; set; }

        protected byte[] Additional { get; set; }
        protected byte[] Secret { get; set; }

        protected void DoTestVector(byte[] password)
        {
            var pbkdfArgon2 =
                HashFactory.KDF.PBKDFArgon2.CreatePBKDFArgon2(password, Builder.Build());

            ActualString = Converters.ConvertBytesToHexString(pbkdfArgon2.GetBytes(ByteCount));

            pbkdfArgon2.Clear();

            AssertAreEqual(ExpectedString, ActualString);
        }
    }
}