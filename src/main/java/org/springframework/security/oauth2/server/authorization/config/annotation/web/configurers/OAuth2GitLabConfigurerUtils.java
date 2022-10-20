package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.GitLabService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryGitLabService;
import org.springframework.security.oauth2.server.authorization.properties.GitLabProperties;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * GitLab OAuth 2.0 配置器的实用方法。
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ConfigurerUtils
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GitLabConfigurerUtils {

	public static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
	}

	public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
	}

	public static GitLabService getGitLabService(HttpSecurity httpSecurity) {
		GitLabService gitLabService = httpSecurity.getSharedObject(GitLabService.class);
		if (gitLabService == null) {
			gitLabService = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, GitLabService.class);
			if (gitLabService == null) {
				GitLabProperties gitLabProperties = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity,
						GitLabProperties.class);
				gitLabService = new InMemoryGitLabService(gitLabProperties);
			}
		}
		return gitLabService;
	}

}
