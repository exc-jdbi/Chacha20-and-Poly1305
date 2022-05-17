
namespace exc.jdbi.Cryptography;

partial class ChaCha20
{
  private void AssertNewInit(byte[] key, byte[] iv, byte[]? tau_sigma, int round)
  {

    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if ((round & 1) == 1 || round < ROUND_MIN)
      throw new ArgumentException(
        $"Round must be even", nameof(round));

    if (key is null || key.Length != KEY_SIZE)
      throw new ArgumentOutOfRangeException(nameof(key),
        $"Key.Length must be {KEY_SIZE}");

    if (iv is null || iv.Length != IV_SIZE)
      throw new ArgumentOutOfRangeException(nameof(iv),
        $"Key.Length must be {IV_SIZE}");

    if (tau_sigma is null) return;

    if (tau_sigma.Length != TAU_SIGMA_SIZE)
      throw new ArgumentOutOfRangeException(nameof(tau_sigma),
        $"tau_sigma.Length must be {TAU_SIGMA_SIZE}");
  }

  private void AssertEncryption(byte[] plain, byte[]? associated = null)
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

  private void AssertEncryption(Stream plain, byte[]? associated = null)
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

    //Real Cipher.Length is Length - TAG_SIZE - ASSOCIATED_SIZE - IV_SIZE
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

    //Real Cipher.Length is Length - TAG_SIZE - ASSOCIATED_SIZE - IV_SIZE
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

  private void ThrowIsDisposed()
    => throw new NotImplementedException(
      $"Chacha20 is disposed !");


  private bool CheckLimit(uint len)
  {
    var old = this.CW[0];
    this.CW[0] += len;
    if (this.CW[0] < old)
      if (++this.CW[1] == 0)
        // 2^(32 + 32 + 6)
        return (++this.CW[2] & 0x20) != 0;
    return false;
  }
}