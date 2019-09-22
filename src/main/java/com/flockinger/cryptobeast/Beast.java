package com.flockinger.cryptobeast;


import static com.flockinger.cryptobeast.InitVectorUtils.IV_SIZE_BYTES;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static org.bouncycastle.util.encoders.Hex.toHexString;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

@ShellComponent
public class Beast {

  private final static String CIPHER_TRANSFORMATION = "AES/CBC/PKCS7Padding";
  private final static String ENCRYPTION_ALGORITHM = "AES";
  private final static String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
  private final static String SHA3_DIGEST_NAME = MessageDigestUtils
      .getDigestName(NISTObjectIdentifiers.id_sha3_256);


  private final Cipher cipher;
  private final SecureRandom random;
  private final MessageDigest sha3Digest;
  private final InitVectorUtils initVectorUtils;


  private byte[] key = null;


  public Beast(InitVectorUtils initVectorUtils) {
    this.initVectorUtils = initVectorUtils;
    try {
      Provider bouncyCastle = new BouncyCastleProvider();
      Security.addProvider(bouncyCastle);
      cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, PROVIDER_NAME);
      random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
      sha3Digest = MessageDigest.getInstance(SHA3_DIGEST_NAME, PROVIDER_NAME);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
      throw new BeastException(CIPHER_TRANSFORMATION + " is not supported by your system!", e);
    }
  }


  @ShellMethod("Encrypt source file content (generate key first with with 'generate-key'!)")
  public void encrypt(@ShellOption File source) {
    String content = readFile(source);

    try {
      IvParameterSpec initVector = createInitVector();
      cipher.init(Cipher.ENCRYPT_MODE, getKey(), initVector);
      byte[] encryptedByteContent = cipher.doFinal(content.getBytes(UTF_8));
      String encryptedContent = toHexString(
          initVectorUtils.addIVToContent(encryptedByteContent, initVector));

      IOUtils.write(encryptedContent, createOutput(source, "ENCRYPTED_"), UTF_8);

    } catch (InvalidKeyException e) {
      throw new BeastException("Key is not a valid AES 256bit key!", e);
    } catch (GeneralSecurityException e) {
      throw new BeastException("Cipher configuration is not valid!", e);
    } catch (IOException e) {
      throw new BeastException("Cannot create encrypted output file!", e);
    }
  }

  private OutputStream createOutput(File source, String prefix) throws FileNotFoundException {
    String filePath = source.toString();
    String fileName = FilenameUtils.getName(source.toString());
    return new FileOutputStream(new File(filePath.replace(fileName, prefix + fileName)));
  }

  private String readFile(File source) {
    try {
      return IOUtils.toString(new FileInputStream(source), UTF_8);
    } catch (IOException e) {
      throw new BeastException("Cannot find file " + source.getName(), e);
    }
  }

  private Key getKey() {
    if (Objects.isNull(key)) {
      throw new BeastException(
          "Please generate key before starting en/decryption with 'generate-key' command!");
    }
    return new SecretKeySpec(key, 0, key.length, ENCRYPTION_ALGORITHM);
  }

  @ShellMethod("Decrypt encrypted source file (generate key first with with 'generate-key'!)")
  public void decrypt(@ShellOption File encryptedSource) {
    String content = readFile(encryptedSource);
    ContentInitVectorPair contentIv = initVectorUtils.extractIVAndContent(Hex.decode(content));

    try {
      cipher.init(Cipher.DECRYPT_MODE, getKey(), new IvParameterSpec(contentIv.getInitvector()));
      String decryptedContent = new String(cipher.doFinal(contentIv.getContent()));

      IOUtils.write(decryptedContent, createOutput(encryptedSource, "DECRYPTED_"), UTF_8);

    } catch (IOException e) {
      throw new BeastException("Cannot create decrypted file!", e);
    } catch (InvalidKeyException e) {
      throw new BeastException("Key is not a valid AES 256bit key!", e);
    } catch (GeneralSecurityException e) {
      throw new BeastException("Cipher configuration is not valid!", e);
    }
  }

  private IvParameterSpec createInitVector() {
    byte[] ivCode = new byte[IV_SIZE_BYTES];
    random.nextBytes(ivCode);
    return new IvParameterSpec(ivCode);
  }


  @ShellMethod("Generates key out of passphrase, can be recreated again and again.")
  public byte[] generateKey(
      @ShellOption(help = "Choose a long and complex Passphrase and don't forget it!!") String passphrase) {
    byte[] passPhraseBytes = passphrase.getBytes(UTF_8);
    sha3Digest.update(passPhraseBytes);

    key = sha3Digest.digest();
    return key;
  }

}
