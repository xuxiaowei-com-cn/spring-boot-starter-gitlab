package org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.GitLabService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryGitLabService;
import org.springframework.security.oauth2.server.authorization.properties.GitLabProperties;

/**
 * GitLab 配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Configuration
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GitLabConfiguration {

	private GitLabProperties gitLabProperties;

	@Autowired
	public void setGitLabProperties(GitLabProperties gitLabProperties) {
		this.gitLabProperties = gitLabProperties;
	}

	@Bean
	@ConditionalOnMissingBean
	public GitLabService gitLabService() {
		return new InMemoryGitLabService(gitLabProperties);
	}

}
