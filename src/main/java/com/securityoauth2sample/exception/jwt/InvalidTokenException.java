package com.securityoauth2sample.exception.jwt;

import com.securityoauth2sample.exception.CustomException;

public class InvalidTokenException extends CustomException {

    private static final String MESSAGE = "올바르지 않은 토큰입니다.";

    public InvalidTokenException() {
        super(MESSAGE);
    }

    @Override
    public int getStatusCode() {
        return 401;
    }
}
