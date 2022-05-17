

namespace exc.jdbi.Cryptography;

using static Convert.Converts;

partial class HChaCha20
{

  private void SetCurrentBlock()
  {
    //Anders als bei ChaCha20 ändert sich in XChaCha20
    //der Currentblock, wenn der iv ausgetauscht wird, 
    //weil vorgängig ein HChaCha20-Key erstellt wird.
    this.ResetCurrentBlock();
    var k = this.HChaChaCore(this.Rounds);
    var result = new uint[CURRENTBLOCK_SIZE]; //ctx
    result[0] = 0x61707865;
    result[1] = 0x3320646e;
    result[2] = 0x79622d32;
    result[3] = 0x6b206574;
    //Alle 32 Bytes vom HChaCha20-Key werden
    //dem Currentblock zugewiesen.
    Array.Copy(k, 0, result, 4, k.Length);
    //Beide CounterIndexes werden beim Erstellen des
    //Currentblockes auf 0 gesetzt.
    //D.h. Wird ein iv-Wechsel eingeleitet, müssen
    //beide CounterIndexes übernommen werden!!
    //Siehe Zeile 58, Function SetIv(...).
    result[12] = 0; result[13] = 0;
    //Die letzten 8 Bytes (von 24) vom iv werden
    //dem Currentblock zugewiesen.
    result[14] = ToUI32(this.MIv, 16);
    result[15] = ToUI32(this.MIv, 20);
    this.CurrentBlock = result;
  }

  private void ResetCurrentBlock()
  {
    if (this.CurrentBlock is not null)
      Array.Clear(this.CurrentBlock, 0, this.CurrentBlock.Length);
    this.CurrentBlock = Array.Empty<uint>();
  }

  protected void SetIv(byte[] iv)
  {
    //Ein Wechsel von iv ändert den Currentblock
    //Nur die ersten 4 Indexes und die CounterIndexes
    //werden gleich bleiben.
    if (this.MIv is not null)
      Array.Clear(this.MIv, 0, this.MIv.Length);

    this.MIv = iv;
    var xy = new uint[2];
    Array.Copy(this.CurrentBlock, 12, xy, 0, 2);
    this.SetCurrentBlock();
    //Aktuelle CounterIndexes übernehmen !!
    Array.Copy(xy, 0, this.CurrentBlock, 12, 2);
  }
}
