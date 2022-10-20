package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 重定向 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectGitLabException extends GitLabException {

	public RedirectGitLabException(String errorCode) {
		super(errorCode);
	}

	public RedirectGitLabException(OAuth2Error error) {
		super(error);
	}

	public RedirectGitLabException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectGitLabException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectGitLabException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

}
