package com.securityoauth2sample.exception.oauth2;

import com.securityoauth2sample.exception.CustomException;

public class InvalidRegistrationId extends CustomException {

    private static final String MESSAGE = "유효하지 않은 Registration Id 입니다.";

    public InvalidRegistrationId() {
        super(MESSAGE);
    }

    @Override
    public int getStatusCode() {
        return 406;
    }
}
