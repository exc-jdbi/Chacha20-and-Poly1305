
namespace exc.jdbi.Cryptography;

partial class ChaCha20Poly1305Ex
{
  partial class HMacPoly1305
  {

    private void InstanceParameters(bool clear_parameters = true)
    {
      //Allocate Heap

      if (clear_parameters)
        this.ClearParameters();
      this.R = new uint[5];
      this.S = new uint[5];
      this.K = new uint[4];
      this.H = new uint[5];
      this.CurrentBlock = new byte[BLOCK_SIZE];
    }

    private void Clear()
    {
      if (this.IsDisposed)
        return;

      this.ClearParameters();
      this.CurrentBlockOffset = 0;
    }

    private void ClearParameters()
    {
      //Reset allocate from Heap
      if (this.R is not null)
        Array.Clear(this.R, 0, this.R.Length);
      if (this.S is not null)
        Array.Clear(this.S, 0, this.S.Length);
      if (this.K is not null)
        Array.Clear(this.K, 0, this.K.Length);
      if (this.H is not null)
        Array.Clear(this.H, 0, this.H.Length);
      if (this.CurrentBlock is not null)
        Array.Clear(this.CurrentBlock, 0, this.CurrentBlock.Length);
      this.CurrentBlock = Array.Empty<byte>();
      this.R = this.S = this.K = this.H = Array.Empty<uint>();
    }

    private void ResetHashParameter()
    {
      this.CurrentBlockOffset = 0;
      if (this.H is not null)
        Array.Clear(this.H, 0, this.H.Length);
    }
  }
}