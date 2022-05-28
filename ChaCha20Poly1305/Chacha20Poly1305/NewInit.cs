

namespace exc.jdbi.Cryptography;

using static Converts.Convert;
using static Randoms.CryptoRandom;

partial class ChaCha20Poly1305Ex
{
  /// <summary>
  /// New Initializes of a new instance of the ChaCha20Poly1305 class with a provided key.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="rounds">Default: Null</param>
  public void NewInit(byte[] key, int rounds = 20)
  => this.NewInit(key, RngBytes(IV_SIZE), rounds);


  /// <summary> 
  /// New Initializes of a new instance of the ChaCha20Poly1305 class with a provided 
  /// key and a iv (nonce).
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="iv">The iv (nonce) associated with this message, which should be a unique value for every operation with the same key.</param>
  /// <param name="rounds">Default: Null</param>
  public void NewInit(byte[] key, byte[] iv, int rounds = 20)
  {
    this.AssertNewInit(key, iv, rounds);

    this.Clear();
    this.SetAllParameters(key, iv, rounds);
  }

  private void SetAllParameters(byte[] key, byte[] iv, int rounds)
  {
    this.MIv = iv.ToArray();
    this.MKey = key.ToArray();
    this.MChaCha20 = new ChaCha20(key, iv, rounds);
    var k = this.MChaCha20.Next_Bytes().Take(32).ToArray();

    this.InstanceParameters(false);
    this.SetKey(k);
    Array.Clear(k, 0, k.Length);
  }

  private void SetKey(byte[] key)
  {
    var t = new uint[4];
    t[0] = ToUI32(key, 0); t[1] = ToUI32(key, 4);
    t[2] = ToUI32(key, 8); t[3] = ToUI32(key, 12);

    this.R[0] = t[0] & 0x03FFFFFFU;
    this.R[1] = ((t[0] >> 26) | (t[1] << 6)) & 0x03FFFF03U;
    this.R[2] = ((t[1] >> 20) | (t[2] << 12)) & 0x03FFC0FFU;
    this.R[3] = ((t[2] >> 14) | (t[3] << 18)) & 0x03F03FFFU;
    this.R[4] = (t[3] >> 8) & 0x000FFFFFU;

    Array.Clear(t, 0, t.Length);

    this.S[1] = ToUI32(key, 16); this.S[2] = ToUI32(key, 20);
    this.S[3] = ToUI32(key, 24); this.S[4] = ToUI32(key, 28);
  }

}
