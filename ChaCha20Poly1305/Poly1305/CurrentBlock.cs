
namespace exc.jdbi.Cryptography;

using static Converts.Convert;

partial class ChaCha20Poly1305Ex
{
  partial class HMacPoly1305
  {
    private void UpdateBlock(byte[] bytes)
    {
      var copied = 0;
      var length = bytes.Length;
      while (length > copied)
      {
        if (this.CurrentBlockOffset == BLOCK_SIZE)
        {
          this.ProcessBlock();
          this.CurrentBlockOffset = 0;
        }

        var tocopy = Math.Min(length - copied, BLOCK_SIZE - this.CurrentBlockOffset);
        Array.Copy(bytes, copied, this.CurrentBlock, this.CurrentBlockOffset, tocopy);
        copied += tocopy;
        this.CurrentBlockOffset += tocopy;
      }
    }

    private byte[] DoFinal()
    {
      var result = new byte[HASH_SIZE];

      if (this.CurrentBlockOffset > 0)
        this.ProcessBlock();

      this.H[1] += this.H[0] >> 26; this.H[0] &= 0x3ffffff;
      this.H[2] += this.H[1] >> 26; this.H[1] &= 0x3ffffff;
      this.H[3] += this.H[2] >> 26; this.H[2] &= 0x3ffffff;
      this.H[4] += this.H[3] >> 26; this.H[3] &= 0x3ffffff;
      this.H[0] += (this.H[4] >> 26) * 5; this.H[4] &= 0x3ffffff;
      this.H[1] += this.H[0] >> 26; this.H[0] &= 0x3ffffff;

      var g = new uint[5];
      g[0] = this.H[0] + 5;
      var b = g[0] >> 26; g[0] &= 0x3ffffff;
      g[1] = this.H[1] + b; b = g[1] >> 26; g[1] &= 0x3ffffff;
      g[2] = this.H[2] + b; b = g[2] >> 26; g[2] &= 0x3ffffff;
      g[3] = this.H[3] + b; b = g[3] >> 26; g[3] &= 0x3ffffff;
      g[4] = this.H[4] + b - (1 << 26);

      b = (g[4] >> 31) - 1;
      var nb = ~b;
      this.H[0] = (this.H[0] & nb) | (g[0] & b);
      this.H[1] = (this.H[1] & nb) | (g[1] & b);
      this.H[2] = (this.H[2] & nb) | (g[2] & b);
      this.H[3] = (this.H[3] & nb) | (g[3] & b);
      this.H[4] = (this.H[4] & nb) | (g[4] & b);
      Array.Clear(g, 0, g.Length);

      var f = new ulong[4];
      f[0] = ((this.H[0]) | (this.H[1] << 26)) + (ulong)this.K[0];
      f[1] = ((this.H[1] >> 6) | (this.H[2] << 20)) + (ulong)this.K[1];
      f[2] = ((this.H[2] >> 12) | (this.H[3] << 14)) + (ulong)this.K[2];
      f[3] = ((this.H[3] >> 18) | (this.H[4] << 8)) + (ulong)this.K[3];

      FromUI32((uint)f[0], result, 0);
      f[1] += (f[0] >> 32);
      FromUI32((uint)f[1], result, 4);
      f[2] += (f[1] >> 32);
      FromUI32((uint)f[2], result, 8);
      f[3] += (f[2] >> 32);
      FromUI32((uint)f[3], result, 12);
      Array.Clear(f, 0, f.Length);

      this.ResetHashParameter();

      return result;
    }

    private void ProcessBlock()
    {
      if (this.CurrentBlockOffset < BLOCK_SIZE)
      {
        this.CurrentBlock[this.CurrentBlockOffset] = 1;
        for (var i = this.CurrentBlockOffset + 1; i < BLOCK_SIZE; i++)
          this.CurrentBlock[i] = 0;
      }

      var t = new ulong[5];
      t[0] = ToUI32(this.CurrentBlock, 0);
      t[1] = ToUI32(this.CurrentBlock, 4);
      t[2] = ToUI32(this.CurrentBlock, 8);
      t[3] = ToUI32(this.CurrentBlock, 12);

      this.H[0] += (uint)(t[0] & 0x3ffffffU);
      this.H[1] += (uint)((((t[1] << 32) | t[0]) >> 26) & 0x3ffffff);
      this.H[2] += (uint)((((t[2] << 32) | t[1]) >> 20) & 0x3ffffff);
      this.H[3] += (uint)((((t[3] << 32) | t[2]) >> 14) & 0x3ffffff);
      this.H[4] += (uint)(t[3] >> 8);

      if (this.CurrentBlockOffset == BLOCK_SIZE)
        this.H[4] += (1 << 24);
      Array.Clear(t, 0, t.Length);

      t[0] = MultUI64(this.H[0], this.R[0]) + MultUI64(this.H[1], this.S[4]) + MultUI64(this.H[2], this.S[3]) + MultUI64(this.H[3], this.S[2]) + MultUI64(this.H[4], this.S[1]);
      t[1] = MultUI64(this.H[0], this.R[1]) + MultUI64(this.H[1], this.R[0]) + MultUI64(this.H[2], this.S[4]) + MultUI64(this.H[3], this.S[3]) + MultUI64(this.H[4], this.S[2]);
      t[2] = MultUI64(this.H[0], this.R[2]) + MultUI64(this.H[1], this.R[1]) + MultUI64(this.H[2], this.R[0]) + MultUI64(this.H[3], this.S[4]) + MultUI64(this.H[4], this.S[3]);
      t[3] = MultUI64(this.H[0], this.R[3]) + MultUI64(this.H[1], this.R[2]) + MultUI64(this.H[2], this.R[1]) + MultUI64(this.H[3], this.R[0]) + MultUI64(this.H[4], this.S[4]);
      t[4] = MultUI64(this.H[0], this.R[4]) + MultUI64(this.H[1], this.R[3]) + MultUI64(this.H[2], this.R[2]) + MultUI64(this.H[3], this.R[1]) + MultUI64(this.H[4], this.R[0]);

      this.H[0] = (uint)t[0] & 0x3ffffff; t[1] += (t[0] >> 26);
      this.H[1] = (uint)t[1] & 0x3ffffff; t[2] += (t[1] >> 26);
      this.H[2] = (uint)t[2] & 0x3ffffff; t[3] += (t[2] >> 26);
      this.H[3] = (uint)t[3] & 0x3ffffff; t[4] += (t[3] >> 26);
      this.H[4] = (uint)t[4] & 0x3ffffff;
      this.H[0] += (uint)(t[4] >> 26) * 5;
      this.H[1] += (this.H[0] >> 26); this.H[0] &= 0x3ffffff;
      Array.Clear(t, 0, t.Length);
    }


    private static ulong MultUI64(uint i1, uint i2)
      => ((ulong)i1) * i2;

  }
}