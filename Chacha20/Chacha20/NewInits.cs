

namespace exc.jdbi.Cryptography;

using static Randoms.CryptoRandom;

partial class ChaCha20
{

  /// <summary>
  /// New initializes of the ChaCha20 class with a provided key.
  /// An iv (nonce) is created randomly.
  /// </summary>
  /// <param name="key">The secret key to use for this initialize.</param>
  /// <param name="round">Default: 20.</param>
  /// <param name="tau_sigma">Default: Null.</param>
  public void NewInit(byte[] key, int round = 20, byte[]? tau_sigma = null)
   => this.NewInit(key, RngBytes(IV_SIZE), round, tau_sigma);

  /// <summary>
  /// New initializes of the ChaCha20 class with a 
  /// provided key and iv.
  /// </summary>
  /// <param name="key">The secret key to use for this initialize.</param>
  /// <param name="iv">The iv (nonce) associated with this initialize, which should be a unique value for every operation with the same key.</param>
  /// <param name="round">Default: 20.</param>
  /// <param name="tau_sigma">Default: Null.</param>
  public void NewInit(byte[] key, byte[] iv, int round = 20, byte[]? tau_sigma = null)
  {
    AssertNewInit(key, iv, tau_sigma, round);
    this.Clear();

    this.Index = 0;
    this.Rounds = round;
    this.CW = new[] { 0u, 0u, 0u };
    this.SetTauSigma(tau_sigma);
    this.SetCurrentBlock(key, iv);
  }

}