package org.myjavasecurity.service;

import org.myjavasecurity.repository.RefreshTokenRepository;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@EnableScheduling
public class TokenCleanupService {

    private final RefreshTokenRepository refreshTokenRepository;

    public TokenCleanupService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    // Runs daily at midnight to purge expired tokens from DB
    @Scheduled(cron = "0 0 0 * * ?")
    @Transactional
    public void purgeExpiredTokens() {
        refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
    }
}