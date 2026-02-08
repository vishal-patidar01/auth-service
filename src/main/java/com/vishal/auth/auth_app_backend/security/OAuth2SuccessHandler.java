package com.vishal.auth.auth_app_backend.security;

import com.vishal.auth.auth_app_backend.entities.Provider;
import com.vishal.auth.auth_app_backend.entities.RefreshToken;
import com.vishal.auth.auth_app_backend.entities.User;
import com.vishal.auth.auth_app_backend.repositories.RefreshTokenRepository;
import com.vishal.auth.auth_app_backend.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@AllArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Successful Authentication");
        logger.info(authentication.toString());

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";
        if(authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("registrationId"+registrationId);
        logger.info("user:" + oAuth2User.getAttributes().toString());

        User user;
        switch (registrationId) {
//            case "google" -> {
//                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
//                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
//                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
//                String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();
//
//                user = User.builder()
//                        .email(email)
//                        .name(name)
//                        .image(picture)
//                        .provider(Provider.GOOGLE)
//                          .enable(true)
//                        .build();
//
//                userRepository.findByEmail(email).ifPresentOrElse(user1 -> {
//                    logger.info("user is there in database");
//                    logger.info(user1.toString());
//                }, () -> {
//                    userRepository.save(user);
//                });
//            }
//            default -> {
//                throw new RuntimeException("Invalid registration id");
//            }


            case "google" -> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttribute("email");
                String name = oAuth2User.getAttribute("name");
                String picture = oAuth2User.getAttribute("picture");

                user = userRepository.findByEmail(email).orElseGet(() -> {
                    User newUser = User.builder()
                            .email(email)
                            .name(name)
                            .image(picture)
                            .provider(Provider.GOOGLE)
                            .providerId(googleId)
                            .enable(true)
                            .build();
//                    return userRepository.save(newUser);

                    return userRepository.findByEmail(email).orElseGet(() -> userRepository.save(newUser));
                });
            }

//            case "github" -> {
//                String name = oAuth2User.getAttributes().getOrDefault("login", "").toString();
//                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
//                String githubId = oAuth2User.getAttributes().getOrDefault("id", "").toString();
//                String image = oAuth2User.getAttributes().getOrDefault("avatar_url", "").toString();
//
//
//                User newUser = User.builder()
//                        .email(email)
//                        .name(name)
//                        .image(image)
//                        .enable(true)
//                        .provider(Provider.GITHUB)
//                        .providerId(githubId)
//                        .build();
//
//                user =  userRepository.findByEmail(email).orElseGet(() -> userRepository.save(newUser));
//            }


//            case "github" -> {
//                String githubID = oAuth2User.getAttributes().getOrDefault("id", "").toString();
//                String email = oAuth2User.getAttribute("email");
//                String name = oAuth2User.getAttribute("login");
//                String image = oAuth2User.getAttribute("avatar_url");
//
//                user = userRepository.findByEmail(email).orElseGet(() -> {
//                    User newUser = User.builder()
//                            .email(email)
//                            .name(name)
//                            .image(image)
//                            .provider(Provider.GITHUB)
//                            .providerId(githubID)
//                            .enable(true)
//                            .build();
////                    return userRepository.save(newUser);
//
//                    return userRepository.findByEmail(email).orElseGet(() -> userRepository.save(newUser));
//                });
//            }

            case "github" -> {

                Object idObj = oAuth2User.getAttribute("id");
                String githubId = String.valueOf(idObj);

                String login = (String) oAuth2User.getAttribute("login");
                String nameAttr = (String) oAuth2User.getAttribute("name");
                String image = (String) oAuth2User.getAttribute("avatar_url");


                String emailAttr = (String) oAuth2User.getAttribute("email");
                String email = (emailAttr == null || emailAttr.isBlank())
                        ? nameAttr + "@github.com"
                        : emailAttr;

//                if(email == null) {
//                    email = nameAttr + "@github.com";
//                }

                // name fallback
                String name = (nameAttr != null && !nameAttr.isBlank())
                        ? nameAttr
                        : login;

                user = userRepository.findByEmail(email).orElseGet(() ->
                        userRepository.save(User.builder()
                                .email(email)
                                .name(name)
                                .image(image)
                                .enable(true)
                                .provider(Provider.GITHUB)
                                .providerId(githubId)
                                .build())
                );
            }


            default -> throw new RuntimeException("Unsupported OAuth provider: " + registrationId);
        }

        String jti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .build();

        refreshTokenRepository.save(refreshTokenOb);
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());

        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());



        response.getWriter().write("Login successful");

    }
}
