

namespace exc.jdbi.Cryptography;

partial class HChaCha20
{
  public bool IsDisposed { get; private set; }

  public const int IV_SIZE = 24;
  public const int TAG_SIZE = 16;
  public const int KEY_SIZE = 32;
  public const int ROUND_MIN = 2;
  protected const int BLOCK_SIZE = 64;
  public const int PLAIN_MIN_SIZE = 10;
  protected const int ASSOCIATED_SIZE = 16;
  private const int CURRENTBLOCK_SIZE = 16;

  private const int HCHACHA_KEY_SIZE = 8;
  private const int HCHACHA_KEYSETUP_SIZE = 16;
  protected int Index = -1, Rounds = -1;
  protected byte[] X = Array.Empty<byte>();
  protected uint[] CW = Array.Empty<uint>();
  private byte[] MKey = Array.Empty<byte>();
  protected byte[] MIv = Array.Empty<byte>();
  protected uint[] CurrentBlock = Array.Empty<uint>();



}
