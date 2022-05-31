

namespace exc.jdbi.Cryptography;

using CRand = Randoms.CryptoRandom;

partial class XChaCha20Poly1305Ex
{
  private bool CheckLimit(uint len)
  {
    var old = this.CW[0];
    this.CW[0] += len;
    if (this.CW[0] < old)
      if (++this.CW[1] == 0)
        // 2^(32 + 32 + 6)
        return (++this.CW[2] & 0x20) != 0;
    return false;
  }
   
}
