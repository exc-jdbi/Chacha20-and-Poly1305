
namespace exc.jdbi.Cryptography;

partial class HMacPoly1305
{
  private void AssertNewInit(byte[] key)
  {
    if (this.IsDisposed)
      throw new NotImplementedException(
        $"Program is disposed!");

    if (key is null || key.Length != KEY_SIZE)
      throw new ArgumentOutOfRangeException(nameof(key),
        $"key must be length = {KEY_SIZE}!");
  }
}
