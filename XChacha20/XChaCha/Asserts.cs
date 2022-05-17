
namespace exc.jdbi.Cryptography;


partial class XChaCha20
{

  private void AssertEncryption(byte[] plain, byte[]? associated)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (plain is null || plain.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(plain));

    if (this.CheckLimit((uint)plain.Length))
      throw new ArgumentOutOfRangeException(nameof(plain),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");

    if (associated is null) return;

    if (associated is null || associated.Length < 1)
      throw new ArgumentOutOfRangeException(nameof(associated));
  }

  private void AssertEncryption(Stream plain, byte[]? associated)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (plain is null || plain.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(plain));

    if (this.CheckLimit((uint)plain.Length))
      throw new ArgumentOutOfRangeException(nameof(plain),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");

    if (associated is null) return;

    if (associated is null || associated.Length < 1)
      throw new ArgumentOutOfRangeException(nameof(associated));
  }

  private void AssertEncryption(string srcfilename, string destfilename, byte[]? associated)
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

    if (this.CheckLimit((uint)fi.Length))
      throw new ArgumentOutOfRangeException(nameof(srcfilename),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");

    if (associated is null) return;

    if (associated is null || associated.Length < 1)
      throw new ArgumentOutOfRangeException(nameof(associated));
  }

  private void AssertDecryption(byte[] cipher)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (cipher is null)
      throw new ArgumentNullException(nameof(cipher));

    if (this.CheckLimit((uint)(cipher.Length - TAG_SIZE - ASSOCIATED_SIZE - IV_SIZE)))
      throw new ArgumentOutOfRangeException(nameof(cipher),
        "The limit of 2^70 bytes per IV has been exceeded. Please change IV.");

  }

  private void AssertDecryption(Stream cipher)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (cipher is null)
      throw new ArgumentNullException(nameof(cipher));

    if (this.CheckLimit((uint)(cipher.Length - TAG_SIZE - ASSOCIATED_SIZE - IV_SIZE)))
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
}
