

namespace exc.jdbi.Cryptography;

using static Convert.Converts;

partial class HChaCha20
{

  private uint[] HChaChaCore(int rounds)
  {
    //HChaCha20-Key generieren.
    var k = this.KeySetup();

    for (var i = 0; i < rounds; i += 2)
    {
      // Odd round
      QR(ref k[0], ref k[4], ref k[8], ref k[12]);
      QR(ref k[1], ref k[5], ref k[9], ref k[13]);
      QR(ref k[2], ref k[6], ref k[10], ref k[14]);
      QR(ref k[3], ref k[7], ref k[11], ref k[15]);

      // Even round                                      
      QR(ref k[0], ref k[5], ref k[10], ref k[15]);
      QR(ref k[1], ref k[6], ref k[11], ref k[12]);
      QR(ref k[2], ref k[7], ref k[8], ref k[13]);
      QR(ref k[3], ref k[4], ref k[9], ref k[14]);
    }

    var result = new uint[HCHACHA_KEY_SIZE];
    Array.Copy(k, result, 4);
    Array.Copy(k, 12, result, 4, result.Length - 4);
    return result;
  }

  private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
  {
    a += b; d ^= a; d = RL(d, 16);
    c += d; b ^= c; b = RL(b, 12);
    a += b; d ^= a; d = RL(d, 8);
    c += d; b ^= c; b = RL(b, 7);
  }

  private static uint RL(uint x, int n)
   => (x << n) | (x >> (32 - n));


  private uint[] KeySetup()
  {
    var result = new uint[HCHACHA_KEYSETUP_SIZE];
    result[0] = 0x61707865;
    result[1] = 0x3320646e;
    result[2] = 0x79622d32;
    result[3] = 0x6b206574;
    //Der ganze Key (32 Bytes) wird in den 
    //HChaCha20-Key einbezogen.
    result[4] = ToUI32(this.MKey, 0);
    result[5] = ToUI32(this.MKey, 4);
    result[6] = ToUI32(this.MKey, 8);
    result[7] = ToUI32(this.MKey, 12);
    result[8] = ToUI32(this.MKey, 16);
    result[9] = ToUI32(this.MKey, 20);
    result[10] = ToUI32(this.MKey, 24);
    result[11] = ToUI32(this.MKey, 28);
    //Die ersten 16 Byte der iv werden in 
    //den HChaCha20-Key einbezogen.
    result[12] = ToUI32(this.MIv, 0);
    result[13] = ToUI32(this.MIv, 4);
    result[14] = ToUI32(this.MIv, 8);
    result[15] = ToUI32(this.MIv, 12);
    return result;
  }
}
