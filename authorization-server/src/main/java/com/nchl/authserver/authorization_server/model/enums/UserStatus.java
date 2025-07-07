package com.nchl.authserver.authorization_server.model.enums;

public enum UserStatus {

    /**
     * The user has registered but has not yet completed the activation process.
     */
    REGISTERED,

    /**
     * The user's mobile banking account has been successfully activated and is fully operational.
     */
    ACTIVATED,

    /**
     * The user's mobile banking access has been deactivated — either voluntarily or by the system.
     */
    DEACTIVATED,

    /**
     * The user's mobile banking access is temporarily suspended, possibly due to suspicious activity or pending verification.
     */
    SUSPENDED,

    /**
     * The user's access is permanently blocked due to a serious violation or administrative action.
     */
    BLOCKED,

    /**
     * The user's activation attempt has failed due to an error, invalid input, or rejection.
     */
    ACTIVATION_FAILED,

    /**
     * The user is in the queue for activation, but the process has not yet completed (e.g., pending verification or checker approval).
     */
    WAITING_ACTIVATION,

    /**
     * The user has been marked for removal from the mobile banking system and will be deleted after a review or waiting period.
     */
    MARKED_FOR_REMOVAL
}
