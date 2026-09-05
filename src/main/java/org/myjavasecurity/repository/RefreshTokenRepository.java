package org.myjavasecurity.repository;

import org.myjavasecurity.entity.RefreshToken;
import org.myjavasecurity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    void deleteByUser(User user);

    @Modifying
    void deleteByExpiryDateBefore(Instant now);
}