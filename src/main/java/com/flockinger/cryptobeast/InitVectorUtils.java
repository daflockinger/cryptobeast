package com.flockinger.cryptobeast;

import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.springframework.stereotype.Component;

@Component
public class InitVectorUtils {

  /**
   * Must be equal to the block size (128 bit for AES) of the algorithm
   */
  public final static int IV_SIZE_BYTES = 16;

  public byte[] addIVToContent(byte[] encryptedContent, IvParameterSpec initVector) {
    return ByteUtils.concatenate(initVector.getIV(), encryptedContent);
  }

  public ContentInitVectorPair extractIVAndContent(byte[] contentInitVector) {
    if (contentInitVector.length <= IV_SIZE_BYTES) {
      throw new BeastException("ContentInitVector too small to contain IV and content!!");
    }
    byte[][] contentIvBytes = ByteUtils.split(contentInitVector, IV_SIZE_BYTES);

    return new ContentInitVectorPair(contentIvBytes[0], contentIvBytes[1]);
  }


}
