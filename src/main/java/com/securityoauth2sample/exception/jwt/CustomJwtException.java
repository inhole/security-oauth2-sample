package com.securityoauth2sample.exception.jwt;

import com.securityoauth2sample.exception.CustomException;

public class CustomJwtException extends CustomException {

    private static final String MESSAGE = "토큰 검증이 실패 되었습니다.";

    public CustomJwtException() {
        super(MESSAGE);
    }

    public CustomJwtException(Throwable cause) {
        super(MESSAGE, cause);
    }

    @Override
    public int getStatusCode() {
        return 500;
    }
}
