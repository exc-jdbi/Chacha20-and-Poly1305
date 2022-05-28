

namespace exc.jdbi.Cryptography;


partial class ChaCha20Poly1305Ex
{
  private void AssertNewInit(byte[] key, byte[] iv, int round)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if ((round & 1) == 1 || round < ROUND_MIN)
      throw new ArgumentException(
        $"Round must be even and Round >= {ROUND_MIN}", nameof(round));

    if (key is null || key.Length != KEY_SIZE)
      throw new ArgumentOutOfRangeException(nameof(key),
        $"Key.Length must be {KEY_SIZE}");

    if (iv is null || iv.Length != IV_SIZE)
      throw new ArgumentOutOfRangeException(nameof(iv),
        $"Iv.Length must be {IV_SIZE}");
  }

  private void AssertEncryption(byte[] plain, byte[] aad)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (plain is null || plain.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(plain));

    //https://cloud.google.com/kms/docs/additional-authenticated-data?hl=de
    if (aad is null || aad.Length < AAD_MIN_SIZE || aad.Length > AAD_MAX_SIZE)
      throw new ArgumentOutOfRangeException(nameof(aad));

    if (this.CheckLimit((uint)plain.Length))
      throw new ArgumentOutOfRangeException(nameof(plain),
        $"The limit of {COUNTER_MAX} per IV (nonce) has been exceeded. Please change IV (nonce).");
  }

  private void AssertEncryption(Stream plain, byte[] aad)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (plain is null || plain.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(plain));

    //https://cloud.google.com/kms/docs/additional-authenticated-data?hl=de
    if (aad is null || aad.Length < AAD_MIN_SIZE || aad.Length > AAD_MAX_SIZE)
      throw new ArgumentOutOfRangeException(nameof(aad));

    if (this.CheckLimit((uint)plain.Length))
      throw new ArgumentOutOfRangeException(nameof(plain),
        $"The limit of {COUNTER_MAX} per IV (nonce) has been exceeded. Please change IV (nonce).");
  }

  private void AssertEncryption(string srcfilename, string destfilename, byte[] aad)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (string.IsNullOrEmpty(srcfilename) || !File.Exists(srcfilename))
      throw new FileNotFoundException(nameof(srcfilename), srcfilename);

    if (string.IsNullOrEmpty(destfilename) || new FileInfo(destfilename) == null)
      throw new ArgumentNullException(nameof(destfilename), destfilename);

    //https://cloud.google.com/kms/docs/additional-authenticated-data?hl=de
    if (aad is null || aad.Length < AAD_MIN_SIZE || aad.Length > AAD_MAX_SIZE)
      throw new ArgumentOutOfRangeException(nameof(aad));

    var fi = new FileInfo(srcfilename);
    if (fi.Length < PLAIN_MIN_SIZE)
      throw new ArgumentOutOfRangeException(nameof(srcfilename),
        $"File.Length < {PLAIN_MIN_SIZE}");

    if (this.CheckLimit((uint)fi.Length))
      throw new ArgumentOutOfRangeException(nameof(srcfilename),
        $"The limit of {COUNTER_MAX} per IV (nonce) has been exceeded. Please change IV (nonce).");
  }

  private void AssertDecryption(byte[] cipher)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (cipher is null)
      throw new ArgumentNullException(nameof(cipher));

    //Real Cipher.Length is >>  Length - TAG_SIZE -  IV_SIZE
    if (this.CheckLimit((uint)(cipher.Length - TAG_SIZE - IV_SIZE)))
      throw new ArgumentOutOfRangeException(nameof(cipher),
        $"The limit of {COUNTER_MAX} per IV (nonce) has been exceeded. Please change IV (nonce).");
  }

  private void AssertDecryption(Stream cipher)
  {
    if (this.IsDisposed)
      this.ThrowIsDisposed();

    if (cipher is null)
      throw new ArgumentNullException(nameof(cipher));

    //Real Cipher.Length is >> Length - TAG_SIZE - IV_SIZE
    if (this.CheckLimit((uint)(cipher.Length - TAG_SIZE - IV_SIZE)))
      throw new ArgumentOutOfRangeException(nameof(cipher),
        $"The limit of {COUNTER_MAX} per IV (nonce) has been exceeded. Please change IV (nonce).");
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
        $"The limit of {COUNTER_MAX} per IV (nonce) has been exceeded. Please change IV (nonce).");
  }

  private void ThrowIsDisposed()
    => throw new NotImplementedException(
      $"Chacha20 is disposed !");


  private bool CheckLimit(uint len)
  {
    //2^(32 + 6)
    this.CW += len;
    return COUNTER_MAX < this.CW;
  }


}
