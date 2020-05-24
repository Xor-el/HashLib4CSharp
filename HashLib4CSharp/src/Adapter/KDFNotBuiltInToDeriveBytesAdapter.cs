using System.Security.Cryptography;
using HashLib4CSharp.Interfaces;

namespace HashLib4CSharp.Adapter
{
    internal sealed class KDFNotBuiltInToDeriveBytesAdapter : DeriveBytes
    {
        private readonly IKDFNotBuiltIn _kdfNotBuiltIn;

        internal KDFNotBuiltInToDeriveBytesAdapter(IKDFNotBuiltIn kdfNotBuiltIn)
        {
            _kdfNotBuiltIn = kdfNotBuiltIn;
        }

        public override byte[] GetBytes(int cb) => _kdfNotBuiltIn.GetBytes(cb);

        public override void Reset()
        {
            // do nothing
        }

        public override string ToString() => $"{GetType().Name}({_kdfNotBuiltIn.Name})";
    }
}