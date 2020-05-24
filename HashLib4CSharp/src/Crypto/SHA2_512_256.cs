using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class SHA2_512_256 : SHA2_512Base
    {
        internal SHA2_512_256() :
            base(32)
        {
        }

        public override IHash Clone() =>
            new SHA2_512_256
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[0] = 0x22312194FC2BF72C;
            State[1] = 0x9F555FA3C84C64C2;
            State[2] = 0x2393B86B6F53B151;
            State[3] = 0x963877195940EABD;
            State[4] = 0x96283EE2A88EFFE3;
            State[5] = 0xBE5E1E2553863992;
            State[6] = 0x2B0199FC2C85B8AA;
            State[7] = 0x0EB72DDC81C52CA2;

            base.Initialize();
        }
    }
}