package org.myjavasecurity.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = true) // password ကို null လက်ခံအောင် ပြင်ပါ
    private String password; // Google Auth သမားများအတွက် Nullable

    private String fullName;

    private String bio;

    private String profilePicture;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProvider provider;

    public enum AuthProvider { LOCAL, GOOGLE }
}