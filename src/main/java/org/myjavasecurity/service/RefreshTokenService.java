package org.myjavasecurity.service;

import org.myjavasecurity.entity.RefreshToken;
import org.myjavasecurity.entity.User;
import org.myjavasecurity.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${app.jwt.refresh-expiration-ms:604800000}") // 7 days
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken rotateRefreshToken(String requestToken) {
        RefreshToken token = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        // 1. REUSE DETECTION: If token was already revoked, someone replayed an old token!
        if (token.isRevoked()) {
            refreshTokenRepository.deleteByUser(token.getUser());
            throw new SecurityException("Breach detected! Token reuse attempted. User logged out everywhere.");
        }

        // 2. EXPIRED TOKEN CHECK
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new login request.");
        }

        // 3. Mark old token as revoked
        token.setRevoked(true);
        refreshTokenRepository.save(token);

        // 4. Issue a brand new Refresh Token
        return createRefreshToken(token.getUser());
    }

    @Transactional
    public void deleteByUserId(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}