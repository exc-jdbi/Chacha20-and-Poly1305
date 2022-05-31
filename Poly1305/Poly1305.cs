//https://datatracker.ietf.org/doc/html/rfc8439#section-2.7
//Poly1305 is not a suitable choice for a PRF.
//(IKEv2 >> a function that accepts a variable-
//length key and a variable-length input)
//Poly1305 prohibits using the same key twice,
//whereas the PRF in IKEv2 is used multiple times
//with the same key.
//Additionally, unlike HMAC, Poly1305 is biased,
//so using it for key derivation would reduce the
//security of the symmetric encryption.

// !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! 
//A Hmac must not simply be replaced with Poly1305.
// !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! 

namespace exc.jdbi.Cryptography;

/// <summary>
/// Initializes a new instance of the Poly1305 class.
/// <para>further modified by © exc-jdbi 2022</para>
/// </summary>
/// <remarks>
/// Special thanks to floodyberry and TimothyMeadows
/// <para><see href="https://github.com/TimothyMeadows"></see></para>
/// <para><see href="https://github.com/floodyberry"></see></para>
/// </remarks>
public sealed partial class Poly1305 : IDisposable
{

  /// <summary>
  /// Initializes a new instance of the Poly1305 class 
  /// with the specified key data.
  /// </summary>
  /// <param name="key">
  /// The secret key for Poly1305 encryption. 
  /// The key The key must be 32 bytes.
  /// </param>
  public Poly1305(byte[] key)
  => this.NewInit(key);

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

  ~Poly1305()
  {
    this.Dispose(false);
  }

  /// <summary>
  /// Releases all resources used by the current 
  /// instance of the Poly1305 class.
  /// </summary>
  public void Dispose()
  {
    this.Dispose(true);
    GC.SuppressFinalize(this);
  }
}

