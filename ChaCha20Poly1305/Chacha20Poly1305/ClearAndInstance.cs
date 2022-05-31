

namespace exc.jdbi.Cryptography;


partial class ChaCha20Poly1305Ex
{

  private void InstanceParameters(bool clear_parameters = true)
  {
    //Allocate Heap

    if (clear_parameters)
      this.ClearParameters();
    this.R = new uint[5];
    this.S = new uint[5];
    this.H = new uint[5];
  }

  private void Clear()
  {
    if (this.IsDisposed)
      return;

    if (this.MChaCha20 is not null)
      this.MChaCha20.Dispose();
    if (this.MIv is not null)
      Array.Clear(this.MIv, 0, this.MIv.Length);
    if (this.MKey is not null)
      Array.Clear(this.MKey, 0, this.MKey.Length);

    this.CW = 0;
    this.MChaCha20 = null;
    this.MIv = Array.Empty<byte>();
    this.MKey = Array.Empty<byte>();

    this.ClearParameters();
  }

  private void ClearParameters()
  {
    //Reset allocate from Heap
    if (this.R is not null)
      Array.Clear(this.R, 0, this.R.Length);
    if (this.S is not null)
      Array.Clear(this.S, 0, this.S.Length);
    if (this.H is not null)
      Array.Clear(this.H, 0, this.H.Length);
    this.R = this.S = this.H = Array.Empty<uint>();
  }

  //private void ResetHashParameter()
  //{
  //  if (this.H is not null)
  //    Array.Clear(this.H, 0, this.H.Length);
  //}
}