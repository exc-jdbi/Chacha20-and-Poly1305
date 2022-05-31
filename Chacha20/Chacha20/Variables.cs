

namespace exc.jdbi.Cryptography;

partial class ChaCha20
{
  private int Index = -1;
  private int Rounds = -1;

  public const int IV_SIZE = 8;
  public const int TAG_SIZE = 16;
  public const int KEY_SIZE = 32;
  public const int ROUND_MIN = 2;
  private const int BLOCK_SIZE = 64;
  public const int PLAIN_MIN_SIZE = 10;
  public const int TAU_SIGMA_SIZE = 16;
  private const int CURRENTBLOCK_SIZE = 16;

  private byte[] X = Array.Empty<byte>();
  private uint[] CW = Array.Empty<uint>();
  private uint[] TauSigma = Array.Empty<uint>();
  private uint[] CurrentBlock = Array.Empty<uint>();

  public bool IsDisposed { get; private set; } = false;
}