package com.securityoauth2sample.exception.jwt;

import com.securityoauth2sample.exception.CustomException;

public class Unauthorized extends CustomException {

    private static final String MESSAGE = "인증이 필요합니다.";

    public Unauthorized() {
        super(MESSAGE);
    }

    @Override
    public int getStatusCode() {
        return 401;
    }
}
