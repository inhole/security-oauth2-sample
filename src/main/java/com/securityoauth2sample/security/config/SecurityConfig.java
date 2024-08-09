package com.securityoauth2sample.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // CORS 설정
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))

                // CSRF 설정
                // 1. 비활성화
//                .csrf(AbstractHttpConfigurer::disable)
                // 2. 기본 설정
//                .csrf(Customizer.withDefaults())
                // 3. 커스텀 설정
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository())
                        // 특정 URL 패턴에 대해 CSRF 보호 비활성화)
                        .ignoringRequestMatchers("/api/no-csrf/**")
                )

                // 세션 설정 NEVER -> 기존에 세션이 존재하면 사용
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER))

                // 권한이 없으면 해당 uri 제외하고 접근 불가
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());

        return http.build();
    }

    /**
     * 커스텀 CSRF 토큰 저장소
     *
     */
    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setParameterName("_csrf");  // 요청 파라미터에서 CSRF 토큰을 받을 때 사용할 파라미터 이름 설정
        repository.setHeaderName("X-CSRF-TOKEN"); // 요청 헤더에서 CSRF 토큰을 받을 때 사용할 헤더 이름 설정
        return repository;
    }

    /**
     * CORS 커스텀 허용
     * @return
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.setAllowedOriginPatterns(List.of("*"));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration); // 모든 경로에 대해서 CORS 설정을 적용

        return source;
    }

}
