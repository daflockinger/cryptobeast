package com.flockinger.cryptobeast;

public class ContentInitVectorPair {

  private byte[] content;
  private byte[] initvector;

  public ContentInitVectorPair(byte[] initvector, byte[] content) {
    this.content = content;
    this.initvector = initvector;
  }

  public byte[] getContent() {
    return content;
  }

  public byte[] getInitvector() {
    return initvector;
  }
}
