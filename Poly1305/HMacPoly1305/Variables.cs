


namespace exc.jdbi.Cryptography;

partial class HMacPoly1305
{

  public const int KEY_SIZE = 32;
  public const int HASH_SIZE = 16;
  private const int BLOCK_SIZE = 16;

  private int CurrentBlockOffset = 0;
  private byte[] CurrentBlock = Array.Empty<byte>();

  /** Polynomial key */
  private uint[] R = Array.Empty<uint>();

  /** Precomputed 5 * r[1..4] */
  private uint[] S = Array.Empty<uint>();

  /** Encrypted nonce */
  private uint[] K = Array.Empty<uint>();

  /** Polynomial accumulator */
  private uint[] H = Array.Empty<uint>();

  public bool IsDisposed { get; private set; } = false;
}
