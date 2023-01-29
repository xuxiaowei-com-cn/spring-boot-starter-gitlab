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
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

	/**
	 * 授予对 API 的完全读/写访问权，包括所有群组和项目、容器镜像库和软件包库。
	 */
	public static final String API = "api";

	/**
	 * 授予对 API 的读访问权，包括所有群组和项目、容器镜像库和软件包库。
	 */
	public static final String READ_API = "read_api";

	/**
	 * 通过 /user API端点授予对通过身份验证的用户概要的只读访问权，该端点包括用户名、公共电子邮件和全名。还授予对 /users 下的只读 API 端点的访问权。
	 */
	public static final String READ_USER = "read_user";

	/**
	 * 使用 Git-over-HTTP 或 Repository Files API 授予对私有项目仓库的只读访问权。
	 */
	public static final String READ_REPOSITORY = "read_repository";

	/**
	 * 使用 Git-over-HTTP (不使用 API)授予对私有项目上的仓库的读写访问权。
	 */
	public static final String WRITE_REPOSITORY = "write_repository";

	/**
	 * 授予对私有项目上的容器镜像库镜像的只读访问权。
	 */
	public static final String READ_REGISTRY = "read_registry";

	/**
	 * 授予对私有项目上的容器镜像库镜像的写访问权。
	 */
	public static final String WRITE_REGISTRY = "write_registry";

	/**
	 * 当以管理员用户身份进行身份验证时，授予作为系统中任何用户执行 API 操作的权限。
	 */
	public static final String SUDO = "sudo";

	/**
	 * 授予使用 OpenID Connect 与 GitLab 进行身份验证的权限。还提供对用户配置文件和组成员关系的只读访问权限。
	 */
	public static final String OPENID = "openid";

	/**
	 * 使用 OpenID Connect 授予对用户配置文件数据的只读访问权。
	 */
	public static final String PROFILE = "profile";

	/**
	 * 使用 OpenID Connect 授予对用户主电子邮件地址的只读访问权。
	 */
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
			String scopeResult;
			if (scope == null) {
				scopeResult = READ_USER;
			}
			else {
				List<String> scopeList = Splitter.on(" ").trimResults().splitToList(scope);
				List<String> legalList = Arrays.asList(API, READ_API, READ_USER, READ_REPOSITORY, WRITE_REPOSITORY,
						READ_REGISTRY, WRITE_REGISTRY, SUDO, OPENID, PROFILE, EMAIL);
				Set<String> scopeResultSet = new HashSet<>();
				scopeResultSet.add(READ_USER);
				for (String sc : scopeList) {
					if (legalList.contains(sc)) {
						scopeResultSet.add(sc);
					}
				}
				scopeResult = Joiner.on(" ").join(scopeResultSet);
			}

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
