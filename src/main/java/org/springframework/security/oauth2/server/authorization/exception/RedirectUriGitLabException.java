package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * GitLab redirectUri 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectUriGitLabException extends GitLabException {

	public RedirectUriGitLabException(String errorCode) {
		super(errorCode);
	}

	public RedirectUriGitLabException(OAuth2Error error) {
		super(error);
	}

	public RedirectUriGitLabException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectUriGitLabException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectUriGitLabException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
