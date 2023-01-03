package org.springframework.security.oauth2.server.authorization.web.authentication;

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

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2GitLabParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2GitLabAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * GitLab OAuth2 用于验证授权授予的 {@link OAuth2GitLabAuthenticationToken}。
 *
 * @author xuxiaowei
 * @since Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationConverter 尝试从 {@link HttpServletRequest} 提取
 * OAuth 2.0 授权代码授权的访问令牌请求，然后将其转换为用于验证授权授权的
 * {@link OAuth2AuthorizationCodeAuthenticationToken} 。
 * @see OAuth2RefreshTokenAuthenticationConverter 用于 OAuth 2.0 授权代码授予的Authentication实现。
 * @see OAuth2ClientCredentialsAuthenticationConverter 尝试从 {@link HttpServletRequest} 提取
 * OAuth 2.0 客户端凭据授予的访问令牌请求，然后将其转换为用于验证授权授予的
 * {@link OAuth2ClientCredentialsAuthenticationToken} 。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GitLabAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {

		// grant_type (REQUIRED)
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!OAuth2GitLabAuthenticationToken.GITLAB.getValue().equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// code (REQUIRED)
		String code = parameters.getFirst(OAuth2ParameterNames.CODE);
		if (!StringUtils.hasText(code) || parameters.get(OAuth2ParameterNames.CODE).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CODE,
					OAuth2GitLabEndpointUtils.AUTH_CODE2SESSION_URI);
		}

		// appid (REQUIRED)
		String appid = parameters.getFirst(OAuth2GitLabParameterNames.APPID);

		if (!StringUtils.hasText(appid) || parameters.get(OAuth2GitLabParameterNames.APPID).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2GitLabParameterNames.APPID,
					OAuth2GitLabEndpointUtils.AUTH_CODE2SESSION_URI);
		}

		// scope
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);

		String state = parameters.getFirst(OAuth2ParameterNames.STATE);

		// 是否绑定，需要使用者自己去拓展
		String binding = request.getParameter(OAuth2GitLabParameterNames.BINDING);

		Map<String, Object> additionalParameters = new HashMap<>(4);
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.CLIENT_ID)
					&& !key.equals(OAuth2ParameterNames.CODE) && !key.equals(OAuth2ParameterNames.REDIRECT_URI)
					&& !key.equals(OAuth2ParameterNames.CLIENT_SECRET) && !key.equals(OAuth2GitLabParameterNames.APPID)
					&& !key.equals(OAuth2ParameterNames.SCOPE) && !OAuth2GitLabParameterNames.REMOTE_ADDRESS.equals(key)
					&& !OAuth2GitLabParameterNames.SESSION_ID.equals(key)
					&& !OAuth2GitLabParameterNames.BINDING.equals(key)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		String remoteAddress = request.getParameter(OAuth2GitLabParameterNames.REMOTE_ADDRESS);
		String sessionId = request.getParameter(OAuth2GitLabParameterNames.SESSION_ID);

		return new OAuth2GitLabAuthenticationToken(clientPrincipal, additionalParameters, appid, code, scope,
				remoteAddress, sessionId, state, binding);
	}

}
