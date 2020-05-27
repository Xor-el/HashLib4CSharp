/*
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
{ *                             HashLib4CSharp Library                              * }
{ *                      Copyright (c) 2020 Ugochukwu Mmaduekwe                     * }
{ *                 GitHub Profile URL <https://github.com/Xor-el>                  * }

{ *  Distributed under the MIT software license, see the accompanying LICENSE file  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *   This library was sponsored by Sphere 10 Software (https://www.sphere10.com)   * }
{ *         for the purposes of supporting the XXX (https://YYY) project.           * }
{ *                                                                                 * }
(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
*/

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