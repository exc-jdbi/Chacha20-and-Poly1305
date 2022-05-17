
using System.Text;

namespace exc.jdbi.Cryptography;

using static Converts.Convert;

partial class ChaCha20
{
  private void SetTauSigma(byte[]? tau_sigma = null)
  => this.TauSigma = tau_sigma is null ? ToTauSigma() : ToUI32s(tau_sigma, 0, 4);

  private void SetCurrentBlock(byte[] key, byte[] iv)
  {
    this.CurrentBlock = new uint[CURRENTBLOCK_SIZE];
    Array.Copy(this.TauSigma, this.CurrentBlock, this.TauSigma.Length);
    ToUI32s(key, 0, this.CurrentBlock, 4, 8);
    ToUI32s(iv, 0, this.CurrentBlock, 14, 2);
  }

  private void SetCounter()
  {
    if (++this.CurrentBlock[12] == 0) ++this.CurrentBlock[13];
  }

  //private void ResetCounter()
  // => this.CurrentBlock[12] = this.CurrentBlock[13] = 0;


  private static uint[] ToTauSigma()
  //Proposed by Prof. D.J. Bernstein
  => ToUI32s(Encoding.ASCII.GetBytes("expand 32-byte k"), 0, 4);


}