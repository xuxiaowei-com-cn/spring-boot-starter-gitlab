package org.springframework.security.oauth2.server.authorization.http;

/*-
 * #%L
 * spring-boot-starter-gitlab
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2GitLabParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.GitLabService;
import org.springframework.security.oauth2.server.authorization.properties.GitLabProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * GitLab 跳转到GitLab授权页面
 *
 * @author xuxiaowei
 * @see <a href="https://docs.gitlab.com/ee/api/oauth2.html">OAuth 2.0身份提供程序API</a>
 * @see <a href="https://docs.gitlab.com/ee/integration/oauth_provider.html">OAuth 2.0
 * provider</a>
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class GitLabAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/gitlab/authorize";

	public static final String AUTHORIZE_URL = "/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s";

	public static final String API = "api";

	public static final String READ_USER = "read_user";

	public static final String READ_REPOSITORY = "read_repository";

	public static final String WRITE_REPOSITORY = "write_repository";

	public static final String READ_REGISTRY = "read_registry";

	public static final String WRITE_REGISTRY = "write_registry";

	public static final String SUDO = "sudo";

	public static final String OPENID = "openid";

	public static final String PROFILE = "profile";

	public static final String EMAIL = "email";

	private GitLabProperties gitLabProperties;

	private GitLabService gitLabService;

	/**
	 * GitLab 授权前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Autowired
	public void setGitLabProperties(GitLabProperties gitLabProperties) {
		this.gitLabProperties = gitLabProperties;
	}

	@Autowired
	public void setGitLabService(GitLabService gitLabService) {
		this.gitLabService = gitLabService;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");

			GitLabProperties.GitLab gitLab = gitLabService.getGitLabByAppid(appid);
			String domain = gitLab.getDomain();

			String redirectUri = gitLabService.getRedirectUriByAppid(appid);

			String binding = request.getParameter(OAuth2GitLabParameterNames.BINDING);
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			List<String> scopeList = Splitter.on(" ").trimResults().splitToList(scope);
			List<String> legalList = Arrays.asList(API, READ_USER, READ_REPOSITORY, WRITE_REPOSITORY, READ_REGISTRY,
					WRITE_REGISTRY, SUDO, OPENID, PROFILE, EMAIL);
			Set<String> scopeResultSet = new HashSet<>();
			scopeResultSet.add(READ_USER);
			for (String sc : scopeList) {
				if (legalList.contains(sc)) {
					scopeResultSet.add(sc);
				}
			}
			String scopeResult = Joiner.on(" ").join(scopeResultSet);

			String state = gitLabService.stateGenerate(request, response, appid);
			gitLabService.storeBinding(request, response, appid, state, binding);
			gitLabService.storeUsers(request, response, appid, state, binding);

			String url = String.format(domain + AUTHORIZE_URL, appid, redirectUri, scopeResult, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
