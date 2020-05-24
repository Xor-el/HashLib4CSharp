using System.Security.Cryptography;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Adapter
{
    internal sealed class KDFNotBuiltInToDeriveBytesAdapter : DeriveBytes
    {
        private readonly IKDFNotBuiltIn _kdfNotBuiltIn;

        internal KDFNotBuiltInToDeriveBytesAdapter(IKDFNotBuiltIn kdfNotBuiltIn)
        {
            _kdfNotBuiltIn = kdfNotBuiltIn != null
                ? kdfNotBuiltIn.Clone()
                : throw new ArgumentNullHashLibException(nameof(kdfNotBuiltIn));
        }

        public override byte[] GetBytes(int cb) => _kdfNotBuiltIn.GetBytes(cb);

        public override void Reset()
        {
            // do nothing
        }

        public override string ToString() => $"{GetType().Name}({_kdfNotBuiltIn.Name})";
    }
}