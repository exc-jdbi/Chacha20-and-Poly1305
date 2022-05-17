

namespace exc.jdbi.Cryptography;

partial class HChaCha20
{

  public void Reset()
   => this.Clear();

  private void Clear()
  {
    if (this.IsDisposed)
      return;
    this.Index = -1;
    this.Rounds = -1;

    this.ResetCurrentBlock();

    if (this.X != Array.Empty<byte>())
      Array.Clear(this.X, 0, this.X.Length);
    if (this.MIv != Array.Empty<byte>())
      Array.Clear(this.MIv, 0, this.MIv.Length);
    if (this.MKey != Array.Empty<byte>())
      Array.Clear(this.MKey, 0, this.MKey.Length);
    if (this.CW != Array.Empty<uint>())
      Array.Clear(this.CW, 0, this.CW.Length);

    this.X = Array.Empty<byte>();
    this.CW = Array.Empty<uint>();
    this.MIv = Array.Empty<byte>();
    this.MKey = Array.Empty<byte>();

  }
}
