package com.securityoauth2sample.exception.member;

import com.securityoauth2sample.exception.CustomException;

public class LoginFailException extends CustomException {

    private static final String MESSAGE = "로그인 실패 되었습니다.";

    public LoginFailException() {
        super(MESSAGE);
    }

    public LoginFailException(Throwable cause) {
        super(MESSAGE, cause);
    }

    @Override
    public int getStatusCode() {
        return 401;
    }
}
