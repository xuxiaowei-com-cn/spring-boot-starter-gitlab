package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * GitLab AppID 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class AppidGitLabException extends GitLabException {

	public AppidGitLabException(String errorCode) {
		super(errorCode);
	}

	public AppidGitLabException(OAuth2Error error) {
		super(error);
	}

	public AppidGitLabException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public AppidGitLabException(OAuth2Error error, String message) {
		super(error, message);
	}

	public AppidGitLabException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
