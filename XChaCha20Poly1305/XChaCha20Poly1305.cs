//https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03

namespace exc.jdbi.Cryptography;


/// <summary> 
/// <para>A Modification of Implementation of Daniel J. Bernstein's ChaCha20 and Poly1305 stream cipher.</para>
/// <para><see href="https://cr.yp.to/chacha/chacha-20080128.pdf"></see></para>
/// <see href="https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03"></see>
/// <para>further modified by © exc-jdbi 2022</para>
/// </summary>
public partial class XChaCha20Poly1305Ex : IDisposable
{

  /// <summary>
  /// Initializes a new instance of the XChaCha20Poly1305Ex class with a provided key and iv.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="iv">The iv (nonce) associated with this Instance, which should be a unique value for every operation with the same key.</param>
  /// <param name="round"></param>
  public XChaCha20Poly1305Ex(byte[] key, byte[] iv, int round = 20)
  => this.NewInit(key, iv, round);

  /// <summary>
  /// Initializes a new instance of the XChaCha20Poly1305Ex class with a provided key.
  /// An iv (nonce) is created randomly.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="round">Default: 20</param>
  public XChaCha20Poly1305Ex(byte[] key, int round = 20)
  => this.NewInit(key, round);


  protected virtual void Dispose(bool disposing)
  {
    if (!this.IsDisposed)
    {
      if (disposing)
      {
      }
      this.Clear();
      this.IsDisposed = true;
    }
  }

  ~XChaCha20Poly1305Ex()
  => Dispose(disposing: false);


  /// <summary>
  /// Releases all resources used by the current 
  /// instance of the XChaCha20Poly1305Ex class.
  /// </summary>
  public void Dispose()
  {
    Dispose(disposing: true);
    GC.SuppressFinalize(this);
  }
}
