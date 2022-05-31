

namespace exc.jdbi.Cryptography;
partial class XChaCha20Poly1305Ex
{
  partial class XHChaCha20
  {
    private int/* Index = -1,*/ Rounds = -1;

    public const int IV_SIZE = 24;//16
    public const int TAG_SIZE = 16;
    public const int KEY_SIZE = 32;
    public const int ROUND_MIN = 2;
    public const int PLAIN_MIN_SIZE = 10; 
    private const int CURRENTBLOCK_SIZE = 16;

    private const int HCHACHA_KEY_SIZE = 8;
    private const int HCHACHA_KEYSETUP_SIZE = 16;
    private byte[] X = Array.Empty<byte>(); 
    private uint[] CurrentBlock = Array.Empty<uint>();

    public bool IsDisposed { get; private set; }
  }
}