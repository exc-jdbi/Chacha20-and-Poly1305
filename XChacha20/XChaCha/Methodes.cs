

namespace exc.jdbi.Cryptography;

using CRand = Randoms.CryptoRandom;

partial class XChaCha20
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
  private void SetCounter()
  {
    if (++this.CurrentBlock[12] == 0) ++this.CurrentBlock[13];
  }

  private byte[] NewIv()
  {
    var result = new byte[IV_SIZE];
    CRand.NextBytes(result);
    return result;
  }
}
