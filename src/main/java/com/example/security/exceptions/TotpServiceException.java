package com.example.security.exceptions;

public class TotpServiceException extends RuntimeException {

    public TotpServiceException(String message) {
        super(message);
    }

    /**
     * Builds an exception with the provided error mesasge and the provided cuase.
     *
     * @param message the error message.
     * @param cause   the cause.
     */
    public TotpServiceException(String message, Throwable cause) {
        super(message, cause);
    }

}
