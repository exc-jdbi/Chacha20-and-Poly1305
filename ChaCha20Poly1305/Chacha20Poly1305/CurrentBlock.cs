

namespace exc.jdbi.Cryptography;


using static Converts.Convert;

using static Extensions.StreamExtensions;

partial class ChaCha20Poly1305Ex
{
  private void Update(byte[] bytes, int offset)
  {
    int readlength;
    var step = BLOCK_SIZE;
    var bufferbytes = new byte[step];
    while ((readlength = bytes.ChunkReader(bufferbytes, offset, bufferbytes.Length)) != 0)
    {
      UpdateBlock(bufferbytes);
      offset += readlength; 
      Array.Clear(bufferbytes,0, bufferbytes.Length);
    }
  }
  private void UpdateBlock(byte[] bytes)
  {
    this.H[0] += ToUI32(bytes, 0) & 0x03ffffff;
    this.H[1] += (ToUI32(bytes, 3) >> 2) & 0x03ffffff;
    this.H[2] += (ToUI32(bytes, 6) >> 4) & 0x03ffffff;
    this.H[3] += (ToUI32(bytes, 9) >>6) & 0x03ffffff;
    this.H[4] += (ToUI32(bytes, 12) >> 8) | (1 << 24);

    var t = new ulong[5];
    t[0] = MultUI64(this.H[0], this.R[0]) + MultUI64(this.H[4], 5UL * this.R[1]) + MultUI64(this.H[3], 5UL * this.R[2]) + MultUI64(this.H[2], 5UL * this.R[3]) + MultUI64(this.H[1], 5UL * this.R[4]);
    t[1] = MultUI64(this.H[1], this.R[0]) + MultUI64(this.H[0], this.R[1]) + MultUI64(this.H[4], 5UL * this.R[2]) + MultUI64(this.H[3], 5UL * this.R[3]) + MultUI64(this.H[2], 5UL * this.R[4]);
    t[2] = MultUI64(this.H[2], this.R[0]) + MultUI64(this.H[1], this.R[1]) + MultUI64(this.H[0], this.R[2]) + MultUI64(this.H[4], 5UL * this.R[3]) + MultUI64(this.H[3], 5UL * this.R[4]);
    t[3] = MultUI64(this.H[3], this.R[0]) + MultUI64(this.H[2], this.R[1]) + MultUI64(this.H[1], this.R[2]) + MultUI64(this.H[0], this.R[3]) + MultUI64(this.H[4], 5UL * this.R[4]);
    t[4] = MultUI64(this.H[4], this.R[0]) + MultUI64(this.H[3], this.R[1]) + MultUI64(this.H[2], this.R[2]) + MultUI64(this.H[1], this.R[3]) + MultUI64(this.H[0], this.R[4]);

    this.H[0] = (uint)t[0] & 0x3ffffff; t[1] += t[0] >> 26;
    this.H[1] = (uint)t[1] & 0x3ffffff; t[2] += t[1] >> 26;
    this.H[2] = (uint)t[2] & 0x3ffffff; t[3] += t[2] >> 26;
    this.H[3] = (uint)t[3] & 0x3ffffff; t[4] += t[3] >> 26;
    this.H[4] = (uint)t[4] & 0x3ffffff; 
    this.H[0] += (uint)(t[4] >> 26) * 5;
    this.H[1] += (this.H[0] >> 26); this.H[0] &= 0x3ffffff;
    Array.Clear(t, 0, t.Length);

  } 

  private byte[] ToTag()
  {
    var result = new byte[HASH_SIZE];

    this.H[2] += (this.H[1] >> 26) & 0x03ffffff;
    this.H[3] += (this.H[2] >> 26) & 0x03ffffff;
    this.H[4] += (this.H[3] >> 26) & 0x03ffffff;
    this.H[0] += ((this.H[4] >> 26) * 5) & 0x03ffffff;
    this.H[1] += (this.H[0] >> 26) & 0x03ffffff;

    var t = this.H.ToArray();
     
    t[0] += 5; t[1] += t[0] >> 26; t[0] &= 0x03ffffff;
    t[2] += t[1] >> 26; t[1] &= 0x03ffffff;
    t[3] += t[2] >> 26; t[2] &= 0x03ffffff;
    t[4] = t[4] - (1 << 26); t[4] = t[4] - (t[3] >> 26);
    t[3] &= 0x03ffffff;

    var mask = (t[4] >> 31) - 1;
    this.H[0] = t[0] & mask | this.H[0] & ~mask;
    this.H[1] = t[1] & mask | this.H[1] & ~mask;
    this.H[2] = t[2] & mask | this.H[2] & ~mask;
    this.H[3] = t[3] & mask | this.H[3] & ~mask;
    this.H[4] = t[4] & mask | this.H[4] & ~mask; 

    var h = new uint[]
    {
      this.H[0] | this.H[1] << 26,
      this.H[1] >> 6 | this.H[2] << 20,
      this.H[2] >> 12 |this.H[3] << 14,
      this.H[3] >> 18 | this.H[4] << 8
    };

    var v = new ulong[4];
    v[0] = (ulong)h[0] + this.S[1];
    v[1] = ((ulong)h[1] + this.S[2]) + (v[0] >> 32);
    v[2] = ((ulong)h[2] + this.S[3]) + (v[1] >> 32);
    v[3] = ((ulong)h[3] + this.S[4]) + (v[2] >> 32);


    Array.Copy(FromUI32((uint)v[0]), result, 4);
    Array.Copy(FromUI32((uint)v[1]), 0, result, 4, 4);
    Array.Copy(FromUI32((uint)v[2]), 0, result, 8, 4);
    Array.Copy(FromUI32((uint)v[3]), 0, result, 12, 4);
    return result;
  } 

  private static ulong MultUI64(uint i1, uint i2)
    => ((ulong)i1) * i2;
  private static ulong MultUI64(uint i1, ulong i2)
    => i1 * i2;

}
