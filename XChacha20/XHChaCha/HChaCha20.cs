

namespace exc.jdbi.Cryptography;

/// <summary> 
/// <para>A Modification of Implementation of Daniel J. Bernstein's ChaCha20 stream cipher.</para>
/// <see href="https://cr.yp.to/chacha/chacha-20080128.pdf"></see>
/// <para>further modified by © exc-jdbi 2022</para>
/// </summary>
public abstract partial class HChaCha20 : IDisposable
{

  private HChaCha20() => this.IsDisposed = false;

  /// <summary>
  /// Initializes a new instance of the ChaCha20 class with a provided key.
  /// An iv (nonce) is created randomly.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="round">Default: 20.</param>
  public HChaCha20(byte[] key, int round = 20) : this()
  => this.NewInit(key, round);

  /// <summary>
  /// Initializes a new instance of the ChaCha20 class with a 
  /// provided key and iv.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="iv">The iv (nonce) associated with this Instance, which should be a unique value for every operation with the same key.</param>
  /// <param name="round">Default: 20.</param>
  public HChaCha20(byte[] key, byte[] iv, int round = 20) : this()
  => this.NewInit(key, iv, round);

  private void Dispose(bool disposing)
  {
    if (!this.IsDisposed)
    {
      if (disposing)
      {
      }
      this.IsDisposed = true;
    }
  }

  ~HChaCha20()
  => this.Dispose(false);

  public void Dispose()
  {
    this.Dispose(true);
    GC.SuppressFinalize(this);
  }
}
