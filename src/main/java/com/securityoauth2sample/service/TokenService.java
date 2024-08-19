package com.securityoauth2sample.service;

import com.securityoauth2sample.domain.Token;
import com.securityoauth2sample.exception.jwt.ExpiredJwtException;
import com.securityoauth2sample.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
public class TokenService {

    private final TokenRepository tokenRepository;

    public void deleteRefreshToken(String memberKey) {
        tokenRepository.deleteById(memberKey);
    }

    @Transactional
    public void saveOrUpdate(String memberKey, String accessToken, String refreshToken) {
        Token token = tokenRepository.findByAccessToken(accessToken)
                .map(o -> o.updateRefreshToken(refreshToken))
                .orElseGet(() -> Token.builder()
                        .id(memberKey)
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build());

        tokenRepository.save(token);
    }

    public Token findByAccessTokenOrThrow(String accessToken) {
        return tokenRepository.findByAccessToken(accessToken)
                .orElseThrow(ExpiredJwtException::new);
    }

    @Transactional
    public void updateToken(String accessToken, Token token) {
        token.updateAccessToken(accessToken);
        tokenRepository.save(token);
    }
}
