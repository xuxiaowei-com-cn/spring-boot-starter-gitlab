package org.springframework.security.oauth2.server.authorization.web.authentication;

/**
 * GitLab OAuth 2.0 协议端点的实用方法
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GitLabEndpointUtils {

	/**
	 * GitLab
	 */
	public static final String AUTH_CODE2SESSION_URI = "https://docs.gitlab.com/ee/api/oauth2.html";

	/**
	 * 错误代码
	 */
	public static final String ERROR_CODE = "C10000";

	/**
	 * 无效错误代码
	 */
	public static final String INVALID_ERROR_CODE = "C20000";

}
