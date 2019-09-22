package com.flockinger.cryptobeast;

public class BeastException extends RuntimeException {

  public BeastException(String message) {
    super(message);
  }

  public BeastException(String message, Throwable cause) {
    super(message, cause);
  }
}
