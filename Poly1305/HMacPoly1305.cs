

namespace exc.jdbi.Cryptography;

/// <summary>
/// Initializes a new instance of the HMacPoly1305 class.
/// <para>further modified by © exc-jdbi 2022</para>
/// </summary>
/// <remarks>
/// Special thanks to floodyberry and TimothyMeadows
/// <para><see href="https://github.com/TimothyMeadows"></see></para>
/// <para><see href="https://github.com/floodyberry"></see></para>
/// </remarks>
public partial class HMacPoly1305 : IDisposable
{

  /// <summary>
  /// Initializes a new instance of the HMacPoly1305 class with the specified key data.
  /// </summary>
  /// <param name="key">
  /// The secret key for HMacPoly1305 encryption. 
  /// The key The key must be 32 bytes.
  /// </param>
  public HMacPoly1305(byte[] key)
  => this.NewInit(key);

  protected virtual void Dispose(bool disposing)
  {
    if (!this.IsDisposed)
    {
      if (disposing)
      {
      }
      this.IsDisposed = true;
    }
  }

  ~HMacPoly1305()
  {
    this.Dispose(false);
  }

  /// <summary>
  /// Releases all resources used by the current instance of the HMacPoly1305 class.
  /// </summary>
  public void Dispose()
  {
    this.Dispose(true);
    GC.SuppressFinalize(this);
  }
}

