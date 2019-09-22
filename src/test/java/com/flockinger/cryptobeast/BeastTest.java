package com.flockinger.cryptobeast;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FileInputStream;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;


public class BeastTest {


  private Beast beast;

  @Before
  public void setup() {
    beast = new Beast(new InitVectorUtils());
  }

  @Test
  public void testEncrypt_withGeneratedKey_shouldEncrypt() throws Exception {
    beast.generateKey("1234");

    beast.encrypt(fromResource("source.txt"));

    File encryptedFile = fromResource("ENCRYPTED_source.txt");

    assertThat(encryptedFile.exists()).isTrue();
    assertThat(IOUtils.toString(new FileInputStream(encryptedFile), UTF_8))
        .isNotBlank();

    encryptedFile.delete();
  }

  @Test(expected = BeastException.class)
  public void testEncrypt_withNoGeneratedKey_shouldThrowException() throws Exception {
    beast.encrypt(fromResource("source.txt"));
  }

  @Test(expected = BeastException.class)
  public void testEncrypt_withNotExistingFile_shouldThrowException() throws Exception {
    beast.generateKey("1234");

    beast.encrypt(new File("/blub/nonExistante.txt"));
  }

  @Test
  public void testDecrypt_withGeneratedKey_shouldDecrypt() throws Exception {
    beast.generateKey("1234");

    beast.decrypt(fromResource("encrypted.txt"));

    File decryptedFile = fromResource("DECRYPTED_encrypted.txt");
    File originalSource = fromResource("source.txt");

    assertThat(decryptedFile.exists()).isTrue();
    assertThat(IOUtils.toString(new FileInputStream(decryptedFile), UTF_8))
        .isNotBlank().isEqualTo(IOUtils.toString(new FileInputStream(originalSource), UTF_8));

    decryptedFile.delete();
  }

  @Test(expected = BeastException.class)
  public void testDecrypt_withNotGeneratedKey_shouldThrowException() throws Exception {
    beast.decrypt(fromResource("encrypted.txt"));
  }

  @Test(expected = BeastException.class)
  public void testDecrypt_withInvalidDecryptedFile_shouldThrowException() throws Exception {
    beast.generateKey("1234");

    beast.decrypt(fromResource("invalidEncrypted.txt"));
  }

  @Test(expected = BeastException.class)
  public void testDecrypt_withNotExistingFile_shouldThrowException() throws Exception {
    beast.generateKey("1234");

    beast.decrypt(new File("nonExistante.txt"));
  }

  private File fromResource(String name) throws Exception {
    return new File(this.getClass().getClassLoader().getResource(name).toURI());
  }

  @Test
  public void testGenerateKey_shouldGenerateCorrectKey() {

    byte[] key = beast.generateKey("1234");

    assertThat(key).hasSize(256 / 8);

    byte[] shouldBeTheSameKeyWithSamePassphrase = beast.generateKey("1234");

    assertThat(key).isEqualTo(shouldBeTheSameKeyWithSamePassphrase);
  }


}