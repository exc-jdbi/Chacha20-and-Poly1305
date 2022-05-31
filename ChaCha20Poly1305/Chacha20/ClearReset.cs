

namespace exc.jdbi.Cryptography;
partial class ChaCha20Poly1305Ex
{
  partial class ChaCha20
  {

    private void Clear()
    {
      if (this.IsDisposed)
        return;

      //this.Index = -1;
      this.Rounds = -1;

      if (this.X is not null)
        Array.Clear(this.X, 0, this.X.Length);
      if (this.CurrentBlock is not null)
        Array.Clear(this.CurrentBlock, 0, this.CurrentBlock.Length);

      this.X = Array.Empty<byte>();
      this.CurrentBlock = Array.Empty<uint>();
    }
  }
}