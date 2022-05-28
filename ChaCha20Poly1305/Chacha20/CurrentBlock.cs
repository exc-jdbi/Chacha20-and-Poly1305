
using System.Text;

namespace exc.jdbi.Cryptography;

using static Converts.Convert;
partial class ChaCha20Poly1305Ex
{
  partial class ChaCha20
  {
    private void SetCurrentBlock(byte[] key, byte[] iv)
    {
      this.CurrentBlock = new uint[CURRENTBLOCK_SIZE];
      Array.Copy(this.TauSigma, this.CurrentBlock, this.TauSigma.Length);
      ToUI32s(key, 0, this.CurrentBlock, 4, 8);
      //Der komplette iv wird auf 13,14,15 verteilt
      //D.h. der Counter ist der Index 12 >> 0 - (2^32-1)
      
      //The complete iv is distributed to 13,14,15
      //I.e.the counter is the index 12 >> 0 - (2 ^ 32 - 1)
      ToUI32s(iv, 0, this.CurrentBlock, 13, 3);
    }

    private void SetCounter()
    {
      //If the counter is 0 again, it must be aborted.
      //This check and abort is already done in Chacha20Poly1305.
      ++this.CurrentBlock[12];
    }

    public byte[] Next_Bytes()
    {
      this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
      this.SetCounter();
      return X.ToArray();
    }

    public uint[] Next()
    {
      var core = ChachaCore(this.Rounds, this.CurrentBlock);
      this.X = FromUI32(core);
      this.SetCounter();
      return core.ToArray();
    }


    private static uint[] ToTauSigma()
    //Proposed by Prof. D.J. Bernstein
    => ToUI32s(Encoding.ASCII.GetBytes("expand 32-byte k"), 0, 4);
  }
}