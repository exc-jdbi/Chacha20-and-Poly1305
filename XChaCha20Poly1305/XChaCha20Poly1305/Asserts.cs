
namespace exc.jdbi.Cryptography;


partial class XChaCha20Poly1305Ex
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

  private void AssertEncryption(byte[] plain, byte[] aad)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (plain is null || plain.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(plain));

    if (aad is null || aad.Length < AAD_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(aad));

    if (this.CheckLimit((uint)plain.Length))
      throw new ArgumentOutOfRangeException(nameof(plain),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");
  }

  private void AssertEncryption(Stream plain, byte[] aad)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (plain is null || plain.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(plain)); 

    if (aad is null || aad.Length < 1)
      throw new ArgumentOutOfRangeException(nameof(aad));

    if (this.CheckLimit((uint)plain.Length))
      throw new ArgumentOutOfRangeException(nameof(plain),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");
  }

  private void AssertEncryption(string srcfilename, string destfilename, byte[] aad)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (string.IsNullOrEmpty(srcfilename) || !File.Exists(srcfilename))
      throw new FileNotFoundException(nameof(srcfilename), srcfilename);

    if (string.IsNullOrEmpty(destfilename) || new FileInfo(destfilename) == null)
      throw new ArgumentNullException(nameof(destfilename), destfilename);

    var fi = new FileInfo(srcfilename);
    if (fi.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(srcfilename),
        $"File.Length < {PLAIN_MIN_SIZE}");

    if (aad is null || aad.Length < 1)
      throw new ArgumentOutOfRangeException(nameof(aad));

    if (this.CheckLimit((uint)fi.Length))
      throw new ArgumentOutOfRangeException(nameof(srcfilename),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");
  }

  private void AssertDecryption(byte[] cipher)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (cipher is null)
      throw new ArgumentNullException(nameof(cipher));

    if (this.CheckLimit((uint)(cipher.Length - TAG_SIZE - IV_SIZE)))
      throw new ArgumentOutOfRangeException(nameof(cipher),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");

  }

  private void AssertDecryption(Stream cipher)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (cipher is null)
      throw new ArgumentNullException(nameof(cipher));

    if (this.CheckLimit((uint)(cipher.Length - TAG_SIZE - IV_SIZE)))
      throw new ArgumentOutOfRangeException(nameof(cipher),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");

  }

  private void AssertDecryption(string srcfilename, string destfilename)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (string.IsNullOrEmpty(srcfilename) || !File.Exists(srcfilename))
      throw new FileNotFoundException(nameof(srcfilename), srcfilename);

    if (string.IsNullOrEmpty(destfilename) || new FileInfo(destfilename) == null)
      throw new ArgumentNullException(nameof(destfilename), destfilename);

    var fi = new FileInfo(srcfilename);
    if (this.CheckLimit((uint)fi.Length))
      throw new ArgumentOutOfRangeException(nameof(srcfilename),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");
  }

  private void ThrowIsDisposed()
   => throw new NotImplementedException(nameof(this.IsDisposed),
       new Exception($"Program is Disposed: {nameof(this.IsDisposed)} = {this.IsDisposed}"));

}
