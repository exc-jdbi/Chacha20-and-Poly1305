

namespace exc.jdbi.Cryptography;

/// <summary> 
/// <para>A Modification of Implementation of Daniel J. Bernstein's ChaCha20 stream cipher.</para>
/// <see href="https://cr.yp.to/chacha/chacha-20080128.pdf"></see>
/// <para>further modified by © exc-jdbi 2022</para>
/// </summary>
public sealed partial class XChaCha20 : HChaCha20
{
  /// <summary>
  /// Initializes a new instance of the XChaCha20 class with a provided key and iv.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="iv">The iv (nonce) associated with this Instance, which should be a unique value for every operation with the same key.</param>
  /// <param name="round"></param>
  public XChaCha20(byte[] key, byte[] iv, int round = 20) : base(key, iv, round)
  {
    //Hier wird der iv mitgeliefert, d.h. der Basis-iv 
    //ist immer der gleiche iv.
  }

  /// <summary>
  /// Initializes a new instance of the XChaCha20 class with a provided key.
  /// An iv (nonce) is created randomly.
  /// </summary>
  /// <param name="key">The secret key to use for this instance.</param>
  /// <param name="round">Default: 20</param>
  public XChaCha20(byte[] key, int round = 20) : base(key, round)
  {
    //Der iv wird in der Basis HChaCha20 'zufällig' generiert. 
  }
}
