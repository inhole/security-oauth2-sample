package com.securityoauth2sample.dto.response;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class LoginResponse {

    @NotBlank
    public String accessToken;

    public LoginResponse(String accessToken) {
        this.accessToken = accessToken;
    }
}
