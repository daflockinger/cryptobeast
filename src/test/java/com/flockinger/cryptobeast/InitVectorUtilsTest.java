package com.flockinger.cryptobeast;

import static com.flockinger.cryptobeast.InitVectorUtils.IV_SIZE_BYTES;
import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import org.junit.Test;


public class InitVectorUtilsTest {

  private InitVectorUtils utils = new InitVectorUtils();

  @Test
  public void testAddIVToContent() {
    SecureRandom secureRandom = new SecureRandom();

    byte[] testIv = new byte[IV_SIZE_BYTES];
    secureRandom.nextBytes(testIv);
    byte[] contentBytes = "Secure stuff".getBytes();

    byte[] contentIv = utils.addIVToContent(contentBytes, new IvParameterSpec(testIv));

    assertThat(contentIv)
        .hasSize(testIv.length + contentBytes.length)
        .contains(contentBytes)
        .startsWith(testIv);
  }

  @Test
  public void testAddIVToContent_andExtractIvAndContent_shouldReturnCorrectResults() {
    SecureRandom secureRandom = new SecureRandom();

    byte[] testIv = new byte[IV_SIZE_BYTES];
    secureRandom.nextBytes(testIv);
    byte[] contentBytes = "Secure stuff".getBytes();

    byte[] contentIv = utils.addIVToContent(contentBytes, new IvParameterSpec(testIv));
    ContentInitVectorPair contentIvPair = utils.extractIVAndContent(contentIv);

    assertThat(contentIvPair.getContent()).containsExactly(contentBytes);
    assertThat(contentIvPair.getInitvector()).containsExactly(testIv);
  }

  @Test
  public void testExtractIVAndContent_withValidContentIv_shouldReturnCorrect() {
    byte[] contentIv = createConcatenatedBytes((byte) 3, 45, (byte) 7, 16);

    ContentInitVectorPair contentIvPair = utils.extractIVAndContent(contentIv);

    assertThat(contentIvPair.getContent()).containsExactly(createBytes((byte) 3, 45));
    assertThat(contentIvPair.getInitvector()).containsExactly(createBytes((byte) 7, 16));
  }

  @Test(expected = BeastException.class)
  public void testExtractIVAndContent_withTooSmallContentIv_shouldThrowException() {
    utils.extractIVAndContent(createBytes((byte) 2, 16));
  }


  private byte[] createConcatenatedBytes(byte content, int contentSize, byte iv, int ivSize) {
    byte[] contentBytes = new byte[contentSize + ivSize];

    for (int index = 0; index < ivSize; index++) {
      contentBytes[index] = iv;
    }
    for (int index = ivSize; index < (contentSize + ivSize); index++) {
      contentBytes[index] = content;
    }
    return contentBytes;
  }

  private byte[] createBytes(byte content, int size) {
    byte[] contentBytes = new byte[size];

    for (int index = 0; index < size; index++) {
      contentBytes[index] = content;
    }
    return contentBytes;
  }

}