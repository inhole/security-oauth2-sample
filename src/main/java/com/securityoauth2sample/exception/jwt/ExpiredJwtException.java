package com.securityoauth2sample.exception.jwt;

import com.securityoauth2sample.exception.CustomException;

public class ExpiredJwtException extends CustomException {

    private static final String MESSAGE = "토큰이 만료되었습니다.";

    public ExpiredJwtException() {
        super(MESSAGE);
    }

    public ExpiredJwtException(Throwable cause) {
        super(MESSAGE, cause);
    }

    @Override
    public int getStatusCode() {
        return 500;
    }
}
