

namespace exc.jdbi.Cryptography;

partial class HChaCha20
{

  private void AssertNewInit(byte[] key, byte[] iv, int round)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (iv is null || iv.Length != IV_SIZE)
      throw new ArgumentOutOfRangeException(nameof(iv),
        $"{nameof(iv)} must be Length = {IV_SIZE}");

    if (key is null || key.Length != KEY_SIZE)
      throw new ArgumentOutOfRangeException(nameof(key),
        $"{nameof(key)} must be Length = {KEY_SIZE}");

    if (round < ROUND_MIN)
      throw new ArgumentException(
        $"Round min. {ROUND_MIN}", nameof(round));
  }

  protected void ThrowIsDisposed()
   => throw new NotImplementedException(nameof(this.IsDisposed),
       new Exception($"Program is Disposed: {nameof(this.IsDisposed)} = {this.IsDisposed}"));

}
