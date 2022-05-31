

namespace exc.jdbi.Cryptography;
partial class XChaCha20Poly1305Ex
{
  partial class XHChaCha20
  {

    public void Reset()
     => this.Clear();

    private void Clear()
    {
      if (this.IsDisposed)
        return; 
      this.Rounds = -1;

      this.ResetCurrentBlock();

      if (this.X != Array.Empty<byte>())
        Array.Clear(this.X, 0, this.X.Length); 

      this.X = Array.Empty<byte>(); 

    }
  }
}