package com.securityoauth2sample.config;

import com.securityoauth2sample.auth.handler.Http403Handler;
import com.securityoauth2sample.auth.handler.Http401Handler;
import com.securityoauth2sample.auth.handler.OAuth2SuccessHandler;
import com.securityoauth2sample.auth.jwt.filter.JwtAuthenticationFilter;
import com.securityoauth2sample.auth.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
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

    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() { // security를 적용하지 않을 리소스
        return web -> web.ignoring()
                .requestMatchers("/error", "/favicon.ico");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository())
                        // 특정 URL 패턴에 대해 CSRF 보호 비활성화)
                        .ignoringRequestMatchers("/api/no-csrf/**")
                )
                .httpBasic(AbstractHttpConfigurer::disable) // 기본 인증 로그인 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // 기본 login form 비활성화
                .logout(AbstractHttpConfigurer::disable) // 기본 logout 비활성화
                .headers(c -> c.frameOptions(
                        FrameOptionsConfig::disable).disable()) // X-Frame-Options 비활성화

                // 세션 설정 NEVER: 기존에 세션이 존재하면 사용, STATELESS: 사용 안함
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize. // 권한이 없으면 해당 uri 제외하고 접근 불가
                        anyRequest().permitAll())

                .oauth2Login(oauth -> // OAuth2 로그인 기능에 대한 여러 설정의 진입점
                        // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정을 담당
                        oauth.userInfoEndpoint(c -> c.userService(oAuth2UserService))
                                .successHandler(oAuth2SuccessHandler))

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e
                        .accessDeniedHandler(new Http403Handler())
                        .authenticationEntryPoint(new Http401Handler())
                );

        return http.build();
    }

    /**
     * 커스텀 CSRF 토큰 저장소
     *
     */
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        // 1. 비활성화
        // .csrf(AbstractHttpConfigurer::disable)
        // 2. 기본 설정
        // .csrf(Customizer.withDefaults())

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
