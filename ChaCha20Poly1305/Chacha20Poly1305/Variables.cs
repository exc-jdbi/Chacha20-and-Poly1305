

namespace exc.jdbi.Cryptography;


partial class ChaCha20Poly1305Ex
{

  private long CW = -1;

  public const int IV_SIZE = 12;
  public const int TAG_SIZE = 16;
  public const int KEY_SIZE = 32;
  public const int ROUND_MIN = 2;
  private const int BLOCK_SIZE = 16;
  public const int AAD_MIN_SIZE = 0;
  public const int AAD_MAX_SIZE = 1024;//1 kiB
  public const int PLAIN_MIN_SIZE = 10;
  public const long COUNTER_MAX = 64L << 32;

  private ChaCha20? MChaCha20 = null;

  private byte[] MIv = Array.Empty<byte>();
  private byte[] MKey = Array.Empty<byte>();  

  private uint[] R = Array.Empty<uint>();
  private uint[] S = Array.Empty<uint>(); 
  private uint[] H = Array.Empty<uint>();

  public bool IsDisposed { get; private set; } = false;

}
