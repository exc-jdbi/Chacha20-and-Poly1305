

namespace exc.jdbi.Cryptography;

partial class ChaCha20
{

  private void Clear()
  {
    if (this.IsDisposed)
      return;

    this.Index = -1;
    this.Rounds = -1;

    if (this.X is not null)
      Array.Clear(this.X, 0, this.X.Length);
    if (this.CW is not null)
      Array.Clear(this.CW, 0, this.CW.Length);
    if (this.TauSigma is not null)
      Array.Clear(this.TauSigma, 0, this.TauSigma.Length);
    if (this.CurrentBlock is not null)
      Array.Clear(this.CurrentBlock, 0, this.CurrentBlock.Length);

    this.X = Array.Empty<byte>();
    this.CW = Array.Empty<uint>();
    this.TauSigma = Array.Empty<uint>();
    this.CurrentBlock = Array.Empty<uint>();
  }
}