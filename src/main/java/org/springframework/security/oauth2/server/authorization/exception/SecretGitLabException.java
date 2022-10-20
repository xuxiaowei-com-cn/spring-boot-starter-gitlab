package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * GitLab Secret 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class SecretGitLabException extends GitLabException {

	public SecretGitLabException(String errorCode) {
		super(errorCode);
	}

	public SecretGitLabException(OAuth2Error error) {
		super(error);
	}

	public SecretGitLabException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public SecretGitLabException(OAuth2Error error, String message) {
		super(error, message);
	}

	public SecretGitLabException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
