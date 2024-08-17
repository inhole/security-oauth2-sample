package com.securityoauth2sample.exception.jwt;

import com.securityoauth2sample.exception.CustomException;

public class ExpectTokenException extends CustomException {

    private static final String MESSAGE = "토큰의 값을 확인할 수 없습니다.";

    public ExpectTokenException() {
        super(MESSAGE);
    }

    @Override
    public int getStatusCode() {
        return 417;
    }
}
