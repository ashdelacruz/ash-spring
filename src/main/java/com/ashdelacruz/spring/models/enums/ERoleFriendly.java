package com.ashdelacruz.spring.models.enums;

public enum ERoleFriendly {
    ADMIN("Admin"),
    MODERATOR("Moderator"),
    USER("User"),
    GUEST("Guest"),
    PENDING("Pending");

    public final String label;

    private ERoleFriendly(String label) {
        this.label = label;
    }
}
