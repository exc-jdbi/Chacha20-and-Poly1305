
namespace exc.jdbi.Cryptography;

using static Converts.Convert;

partial class HMacPoly1305
{
  /// <summary>
  /// New initializes of the HMacPoly1305 class with the specified key data.
  /// </summary>
  /// <param name="key">
  /// The secret key for HMacPoly1305 encryption. 
  /// The key The key must be 32 bytes.
  /// </param>
  public void NewInit(byte[] key)
  {
    this.AssertNewInit(key);

    this.Clear();
    this.InstanceParameters(false);
    this.SetKey(key);

  }

  private void SetKey(byte[] key)
  {
    // Extract r portion of key (and "clamp" the values)
    var t = new uint[4];
    t[0] = ToUI32(key, 0); t[1] = ToUI32(key, 4);
    t[2] = ToUI32(key, 8); t[3] = ToUI32(key, 12);

    // NOTE: The masks perform the key "clamping" implicitly
    this.R[0] = t[0] & 0x03FFFFFFU;
    this.R[1] = ((t[0] >> 26) | (t[1] << 6)) & 0x03FFFF03U;
    this.R[2] = ((t[1] >> 20) | (t[2] << 12)) & 0x03FFC0FFU;
    this.R[3] = ((t[2] >> 14) | (t[3] << 18)) & 0x03F03FFFU;
    this.R[4] = (t[3] >> 8) & 0x000FFFFFU;

    Array.Clear(t, 0, t.Length);

    // Precompute multipliers
    this.S[1] = this.R[1] * 5; this.S[2] = this.R[2] * 5;
    this.S[3] = this.R[3] * 5; this.S[4] = this.R[4] * 5;

    this.K[0] = ToUI32(key, BLOCK_SIZE + 0);
    this.K[1] = ToUI32(key, BLOCK_SIZE + 4);
    this.K[2] = ToUI32(key, BLOCK_SIZE + 8);
    this.K[3] = ToUI32(key, BLOCK_SIZE + 12);
  }
}
