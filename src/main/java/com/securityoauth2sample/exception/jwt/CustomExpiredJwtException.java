package com.securityoauth2sample.exception.jwt;

import com.securityoauth2sample.exception.CustomException;

public class CustomExpiredJwtException extends CustomException {

    private static final String MESSAGE = "토큰이 만료되었습니다.";

    public CustomExpiredJwtException() {
        super(MESSAGE);
    }

    public CustomExpiredJwtException(Throwable cause) {
        super(MESSAGE, cause);
    }

    @Override
    public int getStatusCode() {
        return 500;
    }
}
