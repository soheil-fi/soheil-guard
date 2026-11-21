package com.soheil.guard;

/** A check that could not run for this token (nothing to read there, or no answer); the report lists it as not checked. */
public class NotCheckedException extends RuntimeException {

    public NotCheckedException(String message) {
        super(message);
    }
}
