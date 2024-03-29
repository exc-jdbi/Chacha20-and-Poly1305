﻿
namespace exc.jdbi.Cryptography;


/// <summary>
/// <para>Implementation of Daniel J. Bernstein's ChaCha20Poly1305 stream cipher.</para>
/// <para>
/// ChaCha20-Poly1305 is an Authenticated encryption with additional data (AEAD) 
/// algorithm, that combines the ChaCha20 stream cipher with the Poly1305 message 
/// authentication code.
/// </para>
/// <see href="https://datatracker.ietf.org/doc/html/rfc7539#section-2.8.2"></see>
/// <para>further modified by © exc-jdbi 2022</para>
/// </summary>
/// <remarks>
/// Special thanks to floodyberry
/// <para><see href="https://github.com/floodyberry"></see></para>
/// </remarks>
public sealed partial class ChaCha20Poly1305Ex : IDisposable
{
  private ChaCha20Poly1305Ex() => this.IsDisposed = false;

  /// <summary>
  /// Initializes a new instance of the ChaCha20Poly1305 class with a provided key.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="rounds">Default: Null</param>
  public ChaCha20Poly1305Ex(byte[] key, int rounds = 20) : this()
   => this.NewInit(key, rounds);

  /// <summary>
  /// Initializes a new instance of the ChaCha20Poly1305 class with a provided 
  /// key and a iv (nonce).
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="iv">The iv (nonce) associated with this message, which should be a unique value for every operation with the same key.</param>
  /// <param name="rounds">Default: Null</param>
  public ChaCha20Poly1305Ex(byte[] key, byte[] iv, int rounds = 20) : this()
  => this.NewInit(key, iv, rounds);


  private void Dispose(bool disposing)
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

  ~ChaCha20Poly1305Ex()
   => this.Dispose(disposing: false);

  /// <summary>
  /// Performs application-defined tasks associated with freeing, 
  /// releasing, or resetting unmanaged resources.
  /// </summary>
  public void Dispose()
  {
    this.Dispose(disposing: true);
    GC.SuppressFinalize(this);
  }
}
